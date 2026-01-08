from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict

import xml.etree.ElementTree as ET


def parse_nmap(path: Path) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    data = p.read_text(errors="ignore")
    if p.suffix.lower() == ".xml" or data.lstrip().startswith("<?xml"):
        return _parse_xml(data)
    # try gnmap
    return _parse_gnmap(data)


def _parse_xml(xml_text: str) -> List[Dict]:
    services: List[Dict] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        for ports in host.findall("ports"):
            for port in ports.findall("port"):
                proto = port.attrib.get("protocol", "tcp")
                portid = int(port.attrib.get("portid", "0"))
                state_el = port.find("state")
                state = state_el.attrib.get("state") if state_el is not None else "unknown"
                service_el = port.find("service")
                name = service_el.attrib.get("name", "") if service_el is not None else ""
                product = service_el.attrib.get("product", "") if service_el is not None else ""
                version = service_el.attrib.get("version", "") if service_el is not None else ""
                services.append({
                    "port": portid,
                    "proto": proto,
                    "state": state,
                    "service": name,
                    "product": product,
                    "version": version,
                })
    # keep only open
    return [s for s in services if s.get("state") == "open"]


def _parse_gnmap(text: str) -> List[Dict]:
    services: List[Dict] = []
    # Example: Host: 10.10.10.10 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    m = re.findall(r"Ports:\s*(.*)$", text, flags=re.MULTILINE)
    for ports_str in m:
        for entry in ports_str.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split("/")
            if len(parts) < 5:
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            state = parts[1]
            proto = parts[2]
            service = parts[4] if len(parts) >= 5 else ""
            if state != "open":
                continue
            services.append({
                "port": port,
                "proto": proto,
                "state": state,
                "service": service,
                "product": "",
                "version": "",
            })
    return services
