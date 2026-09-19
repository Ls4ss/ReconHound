"""Zone Transfer Module for DNS AXFR enumeration."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from reconexec.core.models import Finding, FindingType
from reconexec.modules.base import BaseModule

logger = logging.getLogger("reconexec.modules.zone_transfer")

class ZoneTransferModule(BaseModule):
    name = "zonetransfer"
    description = "DNS Zone Transfer (AXFR) enumeration"
    category = "recon"

    async def run(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        findings = []
        if not target or context is None:
            return findings

        # This module only handles domains.
        if context.get("target_type") != "domain":
            return findings

        root_domain = context.get("root_domain") or target
        
        self.notify(f"Attempting AXFR for {root_domain}...")

        # 1. Get Name Servers for the domain
        ns_records = await self._get_nameservers(root_domain)
        if not ns_records:
            self.notify(f"No nameservers found for {root_domain}.")
            return findings

        # 2. Try AXFR on each Name Server
        discovered_subdomains = set()
        for ns in ns_records:
            self.notify(f"Trying AXFR on {ns} for {root_domain}...")
            subs = await self._try_axfr(root_domain, ns)
            if subs:
                self.notify(f"AXFR successful on {ns}! Discovered {len(subs)} subdomains.")
                discovered_subdomains.update(subs)
                break # If one succeeds, no need to query others

        for sub in discovered_subdomains:
            # Create a finding for each discovered subdomain
            findings.append(
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=root_domain,
                    value=sub,
                    source="Zone Transfer",
                    metadata={"nameserver": ns}
                )
            )

        return findings

    async def _get_nameservers(self, domain: str) -> List[str]:
        """Fetch NS records using dig."""
        cmd = ["dig", "+short", "NS", domain]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            if stdout:
                return [line.strip().decode() for line in stdout.splitlines() if line.strip()]
        except Exception as e:
            logger.debug(f"Failed to fetch NS for {domain}: {e}")
        return []

    async def _try_axfr(self, domain: str, nameserver: str) -> List[str]:
        """Attempt an AXFR query using dig."""
        cmd = ["dig", f"@{nameserver}", domain, "AXFR", "+short"]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # Give it a reasonable timeout
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10.0)
            if stdout:
                output = stdout.decode()
                if "Transfer failed" in output or "failed" in output:
                    return []
                
                # Parse output. 'dig AXFR +short' returns just the records.
                # We need to filter and clean up to just A/CNAME targets or the subdomains themselves.
                # A full 'dig AXFR' without +short is easier to parse the left-most column (the subdomain).
                # But let's use standard dig output without +short for reliable parsing.
                return await self._parse_axfr_output(domain, nameserver)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        except Exception as e:
            logger.debug(f"AXFR failed on {nameserver} for {domain}: {e}")
        return []

    async def _parse_axfr_output(self, domain: str, nameserver: str) -> List[str]:
        """Parse standard dig AXFR output."""
        cmd = ["dig", f"@{nameserver}", domain, "AXFR"]
        subs = set()
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=15.0)
            if not stdout:
                return []
            
            output = stdout.decode()
            if "Transfer failed" in output or "status: REFUSED" in output:
                return []

            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                # dig output format: example.com. 3600 IN A 1.2.3.4
                parts = line.split()
                if len(parts) >= 4:
                    record_name = parts[0]
                    # remove trailing dot
                    if record_name.endswith("."):
                        record_name = record_name[:-1]
                    if record_name.endswith(domain) and record_name != domain:
                        subs.add(record_name)
        except Exception:
            pass
        return list(subs)
