import json
import time
from typing import Optional
from pathlib import Path
from reconexec.config import DETECTI_HOME

def check_for_updates(current_version: str, force: bool = False) -> Optional[str]:
    """Check PyPI for a newer version of reconexec, caching the result to avoid spamming."""
    cache_file = DETECTI_HOME / "last_update_check.json"
    
    if cache_file.exists() and not force:
        try:
            data = json.loads(cache_file.read_text())
            if time.time() - data.get("last_check", 0) < 43200: # 12 hours
                cached_newer = data.get("newer_version")
                if cached_newer:
                    from packaging.version import parse, InvalidVersion
                    try:
                        if parse(cached_newer) > parse(current_version):
                            if not force:
                                _print_update_warning(current_version, cached_newer)
                            return cached_newer
                    except InvalidVersion:
                        pass
                return None
        except Exception:
            pass

    try:
        import requests
        resp = requests.get("https://pypi.org/pypi/reconhound/json", timeout=2.0)
        if resp.status_code == 200:
            latest_version = resp.json()["info"]["version"]
            
            from packaging.version import parse, InvalidVersion
            try:
                cv = parse(current_version)
                lv = parse(latest_version)
                is_newer = lv > cv
            except InvalidVersion:
                is_newer = False
            
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps({
                "last_check": time.time(),
                "latest_version": latest_version,
                "newer_version": latest_version if is_newer else None
            }))
            
            if is_newer:
                if not force:
                    _print_update_warning(current_version, latest_version)
                return latest_version
            return None
    except Exception:
        pass
    
    return None

def _print_update_warning(current: str, latest: str) -> None:
    from reconexec.utils.logger import console
    from rich.panel import Panel
    console.print(Panel(
        f"[bold yellow]Notice:[/bold yellow] A new release of [bold cyan]ReconHound[/bold cyan] is available ([dim]{current}[/dim] -> [bold green]{latest}[/bold green])\n"
        f"Run [bold white]pip install --upgrade reconhound[/bold white] to update.",
        border_style="yellow",
        padding=(0, 2)
    ))
