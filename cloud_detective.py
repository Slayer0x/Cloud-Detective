import dns.resolver, os, json, subprocess, ipaddress, sys, argparse
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen
from urllib.error import HTTPError
from threading import Lock, Event
from collections import deque 
from itertools import cycle

console = Console()
output_file = None

# Global event to signal shutdown
shutdown_event = Event()

def banner():
    
    
    colors = cycle(["[bold blue]", "[bold green]", "[bold orange1]", "[bold red]"])
    banner_blocks = [
        "\n"
        " ▄▄· ▄▄▌        ▄• ▄▌·▄▄▄▄      ·▄▄▄▄  ▄▄▄ .▄▄▄▄▄▄▄▄ . ▄▄· ▄▄▄▄▄▪   ▌ ▐·▄▄▄ .",
        "▐█ ▌▪██•  ▪     █▪██▌██▪ ██     ██▪ ██ ▀▄.▀·•██  ▀▄.▀·▐█ ▌▪•██  ██ ▪█·█▌▀▄.▀·",
        "██ ▄▄██▪   ▄█▀▄ █▌▐█▌▐█· ▐█▌    ▐█· ▐█▌▐▀▀▪▄ ▐█.▪▐▀▀▪▄██ ▄▄ ▐█.▪▐█·▐█▐█•▐▀▀▪▄",
        "▐███▌▐█▌▐▌▐█▌.▐▌▐█▄█▌██. ██     ██. ██ ▐█▄▄▌ ▐█▌·▐█▄▄▌▐███▌ ▐█▌·▐█▌ ███ ▐█▄▄▌",
        "·▀▀▀ .▀▀▀  ▀█▄▀▪ ▀▀▀ ▀▀▀▀▀•     ▀▀▀▀▀•  ▀▀▀  ▀▀▀  ▀▀▀ ·▀▀▀  ▀▀▀ ▀▀▀. ▀   ▀▀▀",
        "                                                                   [bold white]By:[/bold white] [bold red]@Slayer0x[/bold red]"
    ]
    
    colored_banner = ""
    for block in banner_blocks:
        current_color = next(colors)
        colored_banner += current_color + block + "\n"
    
    add_message(colored_banner)

AZURE_DOMAINS = [
    "azurewebsites", "cloudapp", "trafficmanager", "azureedge", "blob.core.windows",
    "file.core.windows", "queue.core.windows", "table.core.windows", "redis.cache.windows",
    "search.windows", "azure-api", "azurecr", "vault.azure", "azurefd",
    "accesscontrol.windows", "graph.windows", "biztalk.windows", "azurecontainer",
    "vo.msecnd", "cosmos.azure", "documents.azure", "azmk8s", "management.core.windows",
    "origin.mediaservices.windows", "azure-mobile", "servicebus.windows", "database.windows",
    "visualstudio"
]

GOOGLE_DOMAINS = [
    "googleapis", "appspot", "cloudfunctions", "cloudsql", "compute", "gcp", "gstatic",
    "firebaseio", "google", "goog", "googleusercontent", "googledomains"
]

AWS_DOMAINS = [
    "amazonaws", "cloudfront", "elasticbeanstalk", "elb", "s3", "rds", "lambda", "dynamodb",
    "route53", "api-gateway", "ec2", "lightsail", "cloudformation", "appsync", "amplifyapp"
]

IPRANGE_URLS = {
    "google": "https://www.gstatic.com/ipranges/goog.json",
    "cloud": "https://www.gstatic.com/ipranges/cloud.json",
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json"
}

# Buffer for messages and lock for thread safety
message_buffer = deque(maxlen=100)
print_lock = Lock()

def add_message(message):
    global output_file
    with print_lock:
        message_buffer.append(message)
        console.print(message)
        if output_file:
            with open(output_file, 'a', encoding='utf-8') as f:
                # Remove rich formatting tags for the file output
                clean_message = message.replace("[bold red]", "").replace("[/bold red]", "")\
                                      .replace("[cyan]", "").replace("[/cyan]", "")\
                                      .replace("[green]", "").replace("[/green]", "")\
                                      .replace("[yellow]", "").replace("[/yellow]", "")\
                                      .replace("[bold blue]", "").replace("[/bold blue]", "")\
                                      .replace("[bold green]", "").replace("[/bold green]", "")
                f.write(clean_message + "\n")

# Functions for querying and checking IPs (same as before)
def get_ip_ranges(url, key):
    try:
        data = json.loads(urlopen(url).read())
        return [entry.get(key) for entry in data.get("prefixes", []) if key in entry]
    except (IOError, HTTPError, json.JSONDecodeError) as e:
        add_message(f"[bold red][!] Error retrieving IPs from {url}: {e}[/bold red]")
        return []

def get_azure_ip_ranges():
    try:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        json_path = os.path.join(script_dir, "ServiceTags_Public.json")

        with open(json_path, "r") as f:
            data = json.load(f)
            return [prefix for service in data.get("values", []) for prefix in service.get("properties", {}).get("addressPrefixes", [])]
    except (IOError, json.JSONDecodeError) as e:
        add_message(f"[bold red][!] Error loading Azure JSON file: {e}, download the newest version at -> ([/bold red]https://www.microsoft.com/en-us/download/details.aspx?id=56519[bold red])[/bold red]")
        return []

def is_target_domain(cname, domains):
    try:
        cname = cname.rstrip('.').lower()
        return any(domain in cname for domain in domains)
    except Exception as e:
        add_message(f"[bold red][!] Error checking domain: {e}[/bold red]")
        return False

def is_target_ip(ip, ip_ranges):
    try:
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for cidr in ip_ranges)
    except ValueError:
        return False
    except Exception as e:
        add_message(f"[bold red][!] Error checking IP: {e}[/bold red]")
        return False

def check_domain(domain, azure_ranges, google_ranges, aws_ranges, dns_server=None):
    if shutdown_event.is_set():
        return
    
    # Configure the DNS resolver
    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    
    # A record check
    try:
        a_records = resolver.resolve(domain, "A")
        for ip in a_records:
            if shutdown_event.is_set():
                return
            ip_str = ip.to_text()
            if is_target_ip(ip_str, azure_ranges):
                add_message(f"[cyan]{domain} -> {ip_str} (Azure IP)[/cyan]")
            if is_target_ip(ip_str, google_ranges):
                add_message(f"[green]{domain} -> {ip_str} (Google Cloud IP)[/green]")
            if is_target_ip(ip_str, aws_ranges):
                add_message(f"[yellow]{domain} -> {ip_str} (AWS IP)[/yellow]")
    except dns.exception.DNSException:
        pass
    
    # CNAME record check
    try:
        cname_records = resolver.resolve(domain, "CNAME")
        for cname in cname_records:
            if shutdown_event.is_set():
                return
            cname_str = cname.to_text()
            if is_target_domain(cname_str, AZURE_DOMAINS):
                add_message(f"[cyan]{domain} -> {cname_str} (Azure CNAME)[/cyan]")
            if is_target_domain(cname_str, GOOGLE_DOMAINS):
                add_message(f"[green]{domain} -> {cname_str} (Google Cloud CNAME)[/green]")
            if is_target_domain(cname_str, AWS_DOMAINS):
                add_message(f"[yellow]{domain} -> {cname_str} (AWS CNAME)[/yellow]")
    except dns.exception.DNSException:
        pass
    
    # Check with WhatWeb
    try:
        if shutdown_event.is_set():
            return
        result = subprocess.run(["whatweb", domain], capture_output=True, text=True, timeout=20)
        output = result.stdout.lower()
        if "azure" in output:
            add_message(f"[cyan]{domain} -> (Detected as Azure by WhatWeb)[/cyan]")
        if "google" in output or "gcp" in output:
            add_message(f"[green]{domain} -> (Detected as Google Cloud by WhatWeb)[/green]")
        if "aws" in output or "amazon" in output:
            add_message(f"[yellow]{domain} -> (Detected as AWS by WhatWeb)[/yellow]")
    except FileNotFoundError:
        add_message("[bold red][X] Error: WhatWeb not found. Make sure it is installed and in the PATH.[/bold red]")
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        add_message(f"[bold red][!] Error running WhatWeb on {domain}: {e}[/bold red]")

def main():
    global shutdown_event, output_file
    
    parser = argparse.ArgumentParser(description="Cloud checker script for detecting cloud hosting providers based on domains.")
    parser.add_argument('files', nargs='+', help="Files containing domains to scan")
    parser.add_argument('-d', '--dns', help="Custom DNS server to use for resolution (not required)")
    parser.add_argument('-w', '--workers', type=int, default=10, help="Number of worker threads to use for scanning (default is 10)")
    parser.add_argument('-o', '--output', help="Output file to save results")

    args = parser.parse_args()

    dns_server = args.dns
    filenames = args.files
    num_workers = args.workers
    output_file = args.output

    # Clear output file if it exists
    if output_file:
        open(output_file, 'w').close()

    domains = []
    for filename in filenames:
        try:
            with open(filename, "r") as f:
                domains.extend([line.strip() for line in f if line.strip()])
        except IOError as e:
            add_message(f"[bold red][!] Error opening file {filename}: {e}[/bold red]")
            exit(1)

    # Get IP ranges once at the start
    add_message("[bold blue][*] Loading IP ranges...[/bold blue]")
    azure_ip_ranges = get_azure_ip_ranges()
    google_ip_ranges = get_ip_ranges(IPRANGE_URLS["cloud"], "ipv4Prefix") + get_ip_ranges(IPRANGE_URLS["google"], "ipv4Prefix")
    aws_ip_ranges = get_ip_ranges(IPRANGE_URLS["aws"], "ip_prefix")
    
    add_message(f"[bold green][*] Starting scan for {len(domains)} domains[/bold green]")
    
    # Progress bar setup
    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console
    )
    
    # Using a ThreadPoolExecutor for parallel processing
    try:
        with ThreadPoolExecutor(max_workers=num_workers) as executor, progress:
            task = progress.add_task("[cyan]Scanning domains...", total=len(domains))
            
            futures = {
                executor.submit(
                    check_domain, 
                    domain, 
                    azure_ip_ranges, 
                    google_ip_ranges, 
                    aws_ip_ranges, 
                    dns_server
                ): domain for domain in domains
            }
            
            # Process results as they complete
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    future.result()
                except Exception as e:
                    if not shutdown_event.is_set():
                        add_message(f"[bold red][!] Error processing {domain}: {e}[/bold red]")
                finally:
                    if not shutdown_event.is_set():
                        progress.update(task, advance=1)
                    else:
                        break
        
        if not shutdown_event.is_set():
            add_message("[bold green][+] Scan completed![/bold green]")
    
    except KeyboardInterrupt:
        shutdown_event.set()
        console.print("\n[bold red][X] Scan interrupted by user - Shutting down... Please Wait.[/bold red]")
        # Forcefully shutdown any remaining threads
        executor._threads.clear()
        for thread in executor._threads:
            try:
                thread._stop()
            except:
                pass
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][!] Error in main execution: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    try:
        banner()
        main()
    except KeyboardInterrupt:
        shutdown_event.set()
        console.print("\n[bold red][X] Scan interrupted by user - Shutting down...[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][!] Error in main execution: {e}[/bold red]")
        sys.exit(1)