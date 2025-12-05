import subprocess
import shlex
from fastmcp import FastMCP

# Initialize the FastMCP server
mcp = FastMCP("Kali Suite", dependencies=["mcp"])

def run_shell(cmd: str, timeout: int = 300) -> str:
    """Helper to run shell commands."""
    try:
        # running with shell=True to support pipes and wildcards if needed by the raw command
        # strict timeout to prevent hanging
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            executable="/bin/bash"
        )
        output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        if result.returncode != 0:
            output += f"\n[Process exited with code {result.returncode}]"
        return output
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds."
    except Exception as e:
        return f"Execution Error: {str(e)}"

# -----------------------------------------------------------------------------
# UNIVERSAL EXECUTION TOOL
# -----------------------------------------------------------------------------

@mcp.tool()
def execute_command(command: str) -> str:
    """
    Executes ANY raw shell command in the Kali Linux environment.
    
    Use this tool when no specific wrapper exists for your needs, or when you need
    complex chaining (pipes, redirects) or specific flags not covered by wrappers.
    
    Example inputs:
    - "nmap -sV -p- 192.168.1.10"
    - "masscan -p80 10.0.0.0/8 --rate=1000"
    - "cat /etc/passwd | grep root"
    """
    return run_shell(command)

# -----------------------------------------------------------------------------
# RECON & OSINT WRAPPERS
# -----------------------------------------------------------------------------

@mcp.tool()
def nmap_scan(target: str, ports: str = "top-1000", flags: str = "-sC -sV") -> str:
    """
    Runs an Nmap network scan against a target.
    
    Args:
        target: IP address, range, or hostname (e.g., '192.168.1.1', 'scanme.nmap.org')
        ports: Ports to scan. Defaults to top 1000. Use '-p-' for all ports or '80,443'.
        flags: Additional nmap flags (default '-sC -sV' for scripts and versions).
    """
    if ports == "top-1000":
        port_arg = ""
    else:
        port_arg = f"-p {ports}"
    
    cmd = f"nmap {flags} {port_arg} {target}"
    return run_shell(cmd)

@mcp.tool()
def masscan_scan(target_range: str, ports: str = "80,443", rate: int = 1000) -> str:
    """
    Runs Masscan for high-speed port scanning of large ranges.
    
    Args:
        target_range: CIDR range or IP (e.g., '10.0.0.0/8').
        ports: Ports to scan (comma separated).
        rate: Packet rate (packets per second).
    """
    cmd = f"masscan {target_range} -p{ports} --rate={rate}"
    return run_shell(cmd)

@mcp.tool()
def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10) -> str:
    """
    Runs Gobuster to bruteforce directory and file existence on a web server.
    
    Args:
        url: Base URL (e.g., 'http://target.com').
        wordlist: Path to wordlist inside the container.
        threads: Number of concurrent threads.
    """
    cmd = f"gobuster dir -u {url} -w {wordlist} -t {threads} --no-error"
    return run_shell(cmd)

@mcp.tool()
def subfinder_discover(domain: str) -> str:
    """
    Runs Subfinder to passively discover subdomains.
    
    Args:
        domain: The domain to enumerate (e.g., 'example.com').
    """
    cmd = f"subfinder -d {domain}"
    return run_shell(cmd)

@mcp.tool()
def theharvester_email(domain: str, limit: int = 500) -> str:
    """
    Runs theHarvester to gather emails, subdomains, hosts, employee names.
    
    Args:
        domain: The domain to search.
        limit: Limit on search results per source.
    """
    # Combining common sources
    cmd = f"theHarvester -d {domain} -l {limit} -b google,bing,duckduckgo,linkedin"
    return run_shell(cmd)

@mcp.tool()
def dnsenum_resolve(domain: str) -> str:
    """
    Runs Dnsenum to enumerate DNS info, zone transfers, and subdomains.
    
    Args:
        domain: The domain to analyze.
    """
    cmd = f"dnsenum {domain} --enum"
    return run_shell(cmd)

@mcp.tool()
def whatweb_identify(target: str) -> str:
    """
    Runs WhatWeb to identify CMS, blogging platforms, statistic packages, and web servers.
    
    Args:
        target: URL or hostname.
    """
    cmd = f"whatweb -a 3 {target}"
    return run_shell(cmd)

# -----------------------------------------------------------------------------
# WEB EXPLOITATION WRAPPERS
# -----------------------------------------------------------------------------

@mcp.tool()
def sqlmap_inject(url: str, parameter: str = None, risk: int = 1, level: int = 1, batch: bool = True) -> str:
    """
    Runs SQLmap to detect and exploit SQL injection flaws.
    
    Args:
        url: Target URL (e.g., 'http://site.com/page?id=1').
        parameter: Specific parameter to test (optional).
        risk: Risk level (1-3).
        level: Test level (1-5).
        batch: If True, run non-interactively (accept defaults).
    """
    batch_flag = "--batch" if batch else ""
    param_flag = f"-p {parameter}" if parameter else ""
    cmd = f"sqlmap -u \"{url}\" {param_flag} --risk={risk} --level={level} {batch_flag} --random-agent"
    return run_shell(cmd)

@mcp.tool()
def nikto_web(url: str) -> str:
    """
    Runs Nikto web server scanner for dangerous files, outdated versions, and config issues.
    
    Args:
        url: Base URL or IP.
    """
    cmd = f"nikto -h {url}"
    return run_shell(cmd)

@mcp.tool()
def wpscan_wordpress(url: str, detection_mode: str = "mixed", api_token: str = None) -> str:
    """
    Runs WPScan against a WordPress installation.
    
    Args:
        url: The blog URL.
        detection_mode: 'passive', 'aggressive', or 'mixed'.
        api_token: Optional WPVulnDB API token.
    """
    token_flag = f"--api-token {api_token}" if api_token else ""
    cmd = f"wpscan --url {url} --detection-mode {detection_mode} --enumerate p,t,u {token_flag} --no-header"
    return run_shell(cmd)

@mcp.tool()
def wfuzz_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", hide_codes: str = "404") -> str:
    """
    Runs Wfuzz to brute force web parameters or paths.
    
    Args:
        url: URL with 'FUZZ' keyword (e.g. 'http://site.com/FUZZ').
        wordlist: Path to wordlist.
        hide_codes: Response codes to hide (comma separated).
    """
    cmd = f"wfuzz -c -z file,{wordlist} --hc {hide_codes} {url}"
    return run_shell(cmd)

@mcp.tool()
def commix_inject(url: str, batch: bool = True) -> str:
    """
    Runs Commix for Command Injection vulnerabilities.
    
    Args:
        url: URL to test.
        batch: Non-interactive mode.
    """
    batch_flag = "--batch" if batch else ""
    cmd = f"commix --url=\"{url}\" {batch_flag}"
    return run_shell(cmd)

@mcp.tool()
def xsstrike_scan(url: str) -> str:
    """
    Runs XSStrike for advanced XSS detection.
    
    Args:
        url: Target URL.
    """
    cmd = f"xsstrike -u \"{url}\""
    return run_shell(cmd)

@mcp.tool()
def wafw00f_detect(url: str) -> str:
    """
    Runs WAFW00F to detect Web Application Firewalls.
    
    Args:
        url: Target URL.
    """
    cmd = f"wafw00f {url}"
    return run_shell(cmd)

@mcp.tool()
def dirsearch_scan(url: str, extensions: str = "php,asp,aspx,jsp,html,js") -> str:
    """
    Runs Dirsearch to brute force web paths.
    
    Args:
        url: Target URL.
        extensions: Comma separated list of extensions to look for.
    """
    cmd = f"dirsearch -u {url} -e {extensions} --format=plain"
    return run_shell(cmd)

# -----------------------------------------------------------------------------
# CREDENTIALS & EXPLOITATION WRAPPERS
# -----------------------------------------------------------------------------

@mcp.tool()
def hydra_brute(target: str, service: str, user: str = None, userlist: str = None, password: str = None, passlist: str = None) -> str:
    """
    Runs Hydra for online password cracking.
    
    Args:
        target: IP or Hostname.
        service: Protocol (ssh, ftp, http-post-form, etc).
        user: Single username.
        userlist: Path to username file.
        password: Single password.
        passlist: Path to password file.
    """
    if user:
        u_flag = f"-l {user}"
    elif userlist:
        u_flag = f"-L {userlist}"
    else:
        return "Error: Must provide user or userlist"

    if password:
        p_flag = f"-p {password}"
    elif passlist:
        p_flag = f"-P {passlist}"
    else:
        return "Error: Must provide password or passlist"
        
    cmd = f"hydra {u_flag} {p_flag} {target} {service}"
    return run_shell(cmd)

@mcp.tool()
def john_ripper(file_path: str, format: str = None, wordlist: str = "/usr/share/wordlists/rockyou.txt.gz") -> str:
    """
    Runs John the Ripper (JtR) on a hash file.
    
    Args:
        file_path: Path to the file containing hashes (inside container).
        format: Hash format (optional, e.g., 'raw-md5').
        wordlist: Path to wordlist.
    """
    fmt_flag = f"--format={format}" if format else ""
    cmd = f"john {fmt_flag} --wordlist={wordlist} {file_path}"
    return run_shell(cmd)

@mcp.tool()
def hashcat_crack(hash_value: str, mode: int, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """
    Runs Hashcat against a specific hash.
    
    Args:
        hash_value: The hash string or path to hash file.
        mode: Hashcat mode type (e.g., 0 for MD5, 1000 for NTLM).
        wordlist: Path to wordlist.
    """
    # Note: Hashcat in Docker often requires --force depending on GPU access
    cmd = f"hashcat -m {mode} -a 0 '{hash_value}' {wordlist} --force --show"
    return run_shell(cmd)

@mcp.tool()
def searchsploit_find(query: str) -> str:
    """
    Runs Searchsploit to find exploits in the ExploitDB archive.
    
    Args:
        query: Search terms (e.g., 'apache 2.4', 'windows smb').
    """
    cmd = f"searchsploit {query}"
    return run_shell(cmd)

@mcp.tool()
def metasploit_console(command: str) -> str:
    """
    Runs a command inside the Metasploit Framework Console (msfconsole).
    
    Args:
        command: The msf command to run (e.g., 'use exploit/multi/handler; show options').
    """
    # -x executes commands and then exits (due to how we invoke it via subproc usually, 
    # but here we might want it to just run. -q for quiet).
    cmd = f"msfconsole -q -x \"{command}; exit\""
    return run_shell(cmd)

@mcp.tool()
def aircrack_ng(input_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """
    Runs Aircrack-ng to crack WiFi captures.
    
    Args:
        input_file: Path to .cap file.
        wordlist: Path to wordlist.
    """
    cmd = f"aircrack-ng -w {wordlist} {input_file}"
    return run_shell(cmd)

if __name__ == "__main__":
    mcp.run()
