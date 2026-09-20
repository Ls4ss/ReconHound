"""AlienVault OTX Intelligence Module."""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set

from reconexec.config import settings, is_placeholder_key
from reconexec.core.models import Finding, FindingType, HostInfoData
from reconexec.modules.base import BaseModule

logger = logging.getLogger("reconexec.alienvault")

class AlienVaultModule(BaseModule):
    """AlienVault OTX reconnaissance and threat intelligence collector."""

    name: str = "otx"
    description: str = "AlienVault OTX passive DNS and CVE attribution module"
    category: str = "osint"

    def is_configured(self) -> bool:
        """Check if AlienVault API key is configured."""
        key = settings.alienvault_api_key
        return bool(key and not is_placeholder_key(key))

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Run OTX intel on CVEs or passive DNS on domains/IPs."""
        target = target.strip()
        context = context or {}
        target_type = context.get("target_type", "unknown")

        findings: List[Finding] = []

        # 1. Threat Intel (CVE Attribution)
        cves_to_enrich: Set[str] = set()
        if target.upper().startswith("CVE-"):
            cves_to_enrich.add(target.upper())
        if "cves" in context:
            for c in context["cves"]:
                if isinstance(c, str) and c.upper().startswith("CVE-"):
                    cves_to_enrich.add(c.upper())

        if cves_to_enrich:
            cve_tasks = [self._enrich_cve(cve, target) for cve in cves_to_enrich]
            cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
            for res in cve_results:
                if isinstance(res, list):
                    findings.extend(res)

        # 2. Passive Recon (Domains and IPs)
        if target_type == "domain":
            domain_findings = await self._passive_dns_domain(target)
            findings.extend(domain_findings)
        elif target_type == "ip":
            ip_findings = await self._passive_dns_ip(target)
            findings.extend(ip_findings)

        return findings

    async def _get_otx(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Make an authenticated request to OTX API."""
        if not self.is_configured():
            return None
            
        url = f"https://otx.alienvault.com/api/v1/{endpoint}"
        headers = {"X-OTX-API-KEY": settings.alienvault_api_key}
        try:
            return await self.http_client.get_json(url=url, headers=headers, timeout=15.0)
        except Exception as exc:
            logger.debug(f"AlienVault API error for {endpoint}: {exc}")
            return None

    async def _enrich_cve(self, cve_id: str, target: str) -> List[Finding]:
        """Fetch pulses for a CVE and extract threat actor / malware tags."""
        findings = []
        data = await self._get_otx(f"indicators/cve/{cve_id}/general")
        if not data or "pulse_info" not in data or "pulses" not in data["pulse_info"]:
            return findings

        extracted_tags = set()
        
        for pulse in data["pulse_info"].get("pulses", []):
            adversary = pulse.get("adversary")
            if adversary:
                extracted_tags.add(adversary)
                
            for malware in pulse.get("malware_families", []):
                # Sometimes malware_families is a list of dicts or strings
                if isinstance(malware, str):
                    extracted_tags.add(malware)
                elif isinstance(malware, dict) and "display_name" in malware:
                    extracted_tags.add(malware["display_name"])
                    
            # Filter generic tags, focus on explicit ones
            for tag in pulse.get("tags", []):
                if isinstance(tag, str):
                    t = tag.lower()
                    if t.startswith("apt") or "ransomware" in t or t in ("lazarus", "lockbit", "cl0p", "conti", "blackbasta"):
                        extracted_tags.add(tag)

        for tag in extracted_tags:
            findings.append(
                Finding(
                    type=FindingType.THREAT_ACTOR,
                    target=target,
                    value=f"{cve_id} -> {tag}",
                    source=self.name,
                    metadata={"cve_id": cve_id, "attribution": tag}
                )
            )
            
        return findings

    async def _passive_dns_domain(self, domain: str) -> List[Finding]:
        """Fetch passive DNS for a domain to find subdomains."""
        findings = []
        data = await self._get_otx(f"indicators/domain/{domain}/passive_dns")
        if not data or "passive_dns" not in data:
            return findings

        seen = set()
        for record in data.get("passive_dns", []):
            subdomain = record.get("hostname")
            if subdomain and subdomain not in seen and subdomain.endswith(domain):
                seen.add(subdomain)
                findings.append(
                    Finding(
                        type=FindingType.SUBDOMAIN,
                        target=domain,
                        value=subdomain,
                        source=self.name,
                    )
                )
        return findings

    async def _passive_dns_ip(self, ip: str) -> List[Finding]:
        """Fetch passive DNS for an IP to find virtual hosts."""
        findings = []
        data = await self._get_otx(f"indicators/IPv4/{ip}/passive_dns")
        if not data or "passive_dns" not in data:
            return findings

        seen = set()
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname")
            if hostname and hostname not in seen:
                seen.add(hostname)
                findings.append(
                    Finding(
                        type=FindingType.HOST_INFO,
                        target=ip,
                        value=hostname,
                        source=self.name,
                        host_info=HostInfoData(ip=ip, domains=[hostname], hostnames=[hostname])
                    )
                )
        return findings
