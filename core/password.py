"""Password attack wrappers — hydra, john, hashcat, cewl."""

import re
from core.run import run, run_live


def hydra_brute(target: str, service: str, username: str = "",
                userlist: str = "", passlist: str = "",
                threads: int = 4, callback=None) -> dict:
    """Run hydra brute force attack against a network service.

    Supported services: ssh, ftp, http-get, http-post-form, telnet, smb, mysql, etc.
    """
    cmd = ["hydra", "-l", username] if username else ["-L", userlist] if userlist else ["-l", "admin"]

    if passlist:
        cmd += ["-P", passlist]
    else:
        cmd += ["-p", "admin"]  # default: just test 'admin'

    cmd += ["-t", str(threads), "-f", "-vV"]
    cmd += [target, service]

    output = []
    if callback:
        run_live(cmd, timeout=600, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=600)
        output = out.splitlines()

    creds = []
    for line in output:
        # hydra: [22][ssh] host: 192.168.1.1   login: admin   password: admin123
        m = re.search(r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)", line)
        if m:
            creds.append({
                "port": m.group(1), "service": m.group(2),
                "host": m.group(3), "username": m.group(4), "password": m.group(5),
            })

    status = "complete"
    if creds:
        status = "found"
    elif any("0 valid password" in l or "all attempts failed" in l for l in output):
        status = "failed"

    return {"target": target, "service": service, "creds": creds, "total": len(creds),
            "status": status, "raw": output}


def john_crack(hashfile: str, wordlist: str = "", fmt: str = "", callback=None) -> dict:
    """Run john the ripper against a hash file."""
    cmd = ["john"]
    if wordlist:
        cmd += ["--wordlist=" + wordlist]
    if fmt:
        cmd += ["--format=" + fmt]
    cmd += [hashfile]

    output = []
    if callback:
        run_live(cmd, timeout=300, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=300)
        output = out.splitlines()

    cracks = []
    for line in output:
        # john output: hash:password
        if ":" in line and not line.startswith("[") and not line.startswith("Using"):
            parts = line.strip().split(":", 1)
            if len(parts) == 2 and parts[0] and parts[1]:
                cracks.append({"hash": parts[0], "password": parts[1]})

    # Also try --show
    show_cmd = ["john", "--show"]
    if wordlist:
        show_cmd += ["--wordlist=" + wordlist]
    if fmt:
        show_cmd += ["--format=" + fmt]
    show_cmd += [hashfile]
    show_out = run(show_cmd, timeout=30)
    for line in show_out.splitlines():
        if ":" in line and not line.startswith("Loaded") and not line.startswith("0"):
            parts = line.strip().split(":", 1)
            if len(parts) == 2:
                cracks.append({"hash": parts[0], "password": parts[1]})

    return {"hashfile": hashfile, "cracks": cracks, "total": len(cracks), "raw": output}


def hashcat_crack(hashfile: str, hashtype: int = 0, wordlist: str = "",
                  rules: str = "", callback=None) -> dict:
    """Run hashcat against a hash file.

    Common hash types: 0=MD5, 1000=NTLM, 1400=SHA256, 1800=sha512crypt
    """
    cmd = ["hashcat", "-m", str(hashtype), "-a", "0"]
    if wordlist:
        cmd.append(wordlist)
    else:
        cmd.append("/usr/share/wordlists/rockyou.txt")
    cmd.append(hashfile)

    if rules:
        cmd += ["-r", rules]

    output = []
    if callback:
        run_live(cmd, timeout=600, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=600)
        output = out.splitlines()

    cracks = []
    for line in output:
        m = re.match(r"^([0-9a-f]+):(.+)$", line.strip())
        if m:
            cracks.append({"hash": m.group(1), "password": m.group(2)})

    # Also try hashcat --show
    show_cmd = ["hashcat", "-m", str(hashtype), "--show", hashfile]
    show_out = run(show_cmd, timeout=30)
    for line in show_out.splitlines():
        m = re.match(r"^([0-9a-f]+):(.+)$", line.strip())
        if m:
            cracks.append({"hash": m.group(1), "password": m.group(2)})

    return {"hashfile": hashfile, "hashtype": hashtype, "cracks": cracks,
            "total": len(cracks), "raw": output}


def cewl_wordlist(url: str, depth: int = 2, min_length: int = 6, callback=None) -> dict:
    """Run cewl to generate a wordlist from a website."""
    output_file = f"/tmp/cewl_output_{url.replace('/', '_')}.txt"
    cmd = ["cewl", "-d", str(depth), "-m", str(min_length), "-w", output_file, url]

    output = []
    if callback:
        run_live(cmd, timeout=120, line_callback=lambda l: (output.append(l), callback(l)))
    else:
        out = run(cmd, timeout=120)
        output = out.splitlines()

    word_count = 0
    try:
        with open(output_file) as f:
            words = f.read().splitlines()
            word_count = len(words)
    except FileNotFoundError:
        pass

    return {"url": url, "output_file": output_file, "word_count": word_count, "raw": output}
