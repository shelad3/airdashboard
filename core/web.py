"""Web reconnaissance wrappers — nikto, gobuster, whatweb, sqlmap, wpscan, ffuf."""

import re
from core.run import run, run_live


def nikto_scan(target: str, port: str = "80", callback=None) -> dict:
    """Run nikto web server vulnerability scan."""
    cmd = ["nikto", "-h", target, "-p", port, "-Format", "csv"]
    output = []
    if callback:
        exit_code = run_live(cmd, timeout=120, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=120)
        output = out.splitlines()
        exit_code = 0

    vulns = []
    for line in output:
        line = line.strip()
        if not line or line.startswith("host,"):
            continue
        parts = line.split(",", 2)
        if len(parts) >= 2:
            osvdb = parts[0].strip().strip('"')
            desc = parts[1].strip().strip('"') if len(parts) > 1 else ""
            if osvdb and osvdb != "OSVDB" and desc:
                vulns.append({"id": osvdb, "description": desc})

    return {"target": target, "port": port, "vulns": vulns, "total": len(vulns), "raw": output}


def gobuster_dir(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                 extensions: str = "php,html,js,txt", callback=None) -> dict:
    """Run gobuster directory brute force."""
    cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-x", extensions, "-q", "--no-error"]
    output = []
    if callback:
        run_live(cmd, timeout=180, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=180)
        output = out.splitlines()

    dirs = []
    for line in output:
        m = re.match(r"(\/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
        if m:
            dirs.append({"path": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})

    return {"target": target, "dirs": dirs, "total": len(dirs), "raw": output}


def gobuster_dns(target: str, wordlist: str = "/usr/share/wordlists/dns/namelist.txt",
                 callback=None) -> dict:
    """Run gobuster DNS subdomain brute force."""
    cmd = ["gobuster", "dns", "-d", target, "-w", wordlist, "-q"]
    output = []
    if callback:
        run_live(cmd, timeout=120, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=120)
        output = out.splitlines()

    subs = []
    for line in output:
        m = re.search(r"Found:\s+(\S+\." + re.escape(target) + r")", line)
        if m:
            subs.append(m.group(1))

    return {"target": target, "subdomains": subs, "total": len(subs), "raw": output}


def whatweb_scan(target: str, callback=None) -> dict:
    """Run whatweb technology fingerprinting."""
    cmd = ["whatweb", "--color=never", "--log-json=-", target]
    output = []
    if callback:
        run_live(cmd, timeout=60, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=60)
        output = out.splitlines()

    techs = []
    for line in output:
        # whatweb outputs JSON objects per line
        line = line.strip()
        if line.startswith("{"):
            try:
                import json
                data = json.loads(line)
                plugins = data.get("plugins", {})
                for name, info in plugins.items():
                    if name not in ("IP", "Country", "UncommonHeaders"):
                        version = info.get("version", [""])[0] if isinstance(info.get("version"), list) else ""
                        techs.append({"name": name, "version": version})
            except (json.JSONDecodeError, KeyError):
                pass

    return {"target": target, "technologies": techs, "total": len(techs), "raw": output}


def sqlmap_scan(target_url: str, level: int = 1, risk: int = 1, callback=None) -> dict:
    """Run sqlmap SQL injection scan."""
    cmd = ["sqlmap", "-u", target_url, f"--level={level}", f"--risk={risk}",
           "--batch", "--output-dir=/tmp/sqlmap_out"]
    output = []
    if callback:
        run_live(cmd, timeout=300, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=300)
        output = out.splitlines()

    injections = []
    for line in output:
        if "injectable" in line.lower() or "vulnerable" in line.lower():
            injections.append(line.strip())
        m = re.search(r"Parameter:\s+(\S+)\s+\(", line)
        if m:
            injections.append(f"Parameter: {m.group(1)}")

    return {"target": target_url, "injections": injections, "total": len(injections), "raw": output}


def wpscan_scan(target_url: str, enumerate: str = "ap,at,u", callback=None) -> dict:
    """Run wpscan WordPress security scan."""
    cmd = ["wpscan", "--url", target_url, "--enumerate", enumerate,
           "--format", "cli-no-colour", "--no-banner"]
    output = []
    if callback:
        run_live(cmd, timeout=180, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=180)
        output = out.splitlines()

    findings = []
    for line in output:
        line_s = line.strip()
        if not line_s:
            continue
        if any(k in line_s.lower() for k in ("vulnerability", "vuln", "cve", "wpvdb", "interesting finding", "version")):
            findings.append(line_s)

    return {"target": target_url, "findings": findings, "total": len(findings), "raw": output}


def ffuf_fuzz(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = "php,html,txt", callback=None) -> dict:
    """Run ffuf directory/parameter fuzzing."""
    FUZZ_URL = target_url.rstrip("/") + "/FUZZ" if "/FUZZ" not in target_url else target_url
    cmd = ["ffuf", "-u", FUZZ_URL, "-w", wordlist, "-e", f",.{extensions.replace(',', ',.')}", "-of", "csv", "-mc", "200,301,302,403"]
    output = []
    if callback:
        run_live(cmd, timeout=120, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=120)
        output = out.splitlines()

    results = []
    for line in output:
        parts = line.split(",")
        if len(parts) >= 4 and parts[0] != "FUZZ":
            path = parts[0].strip('"')
            status = parts[1].strip('"')
            size = parts[2].strip('"')
            words = parts[3].strip('"')
            results.append({"path": path, "status": status, "size": size, "words": words})

    return {"target": target_url, "results": results, "total": len(results), "raw": output}
