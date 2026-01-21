import requests
import whois
import dns.resolver
import json
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import re
import time
from fpdf import FPDF # Using standard fpdf to ensure environment compatibility
from fpdf.enums import Align # For fpdf2 compatibility (if needed)

# --- Global Configuration ---
CONSOLE = Console()
DATA_DIR = os.path.expanduser("~/.sro_data")
DB_PATH = os.path.join(DATA_DIR, "sro_db.json")

# --- Utility Functions ---

def load_db():
    """Loads the configuration database."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(DB_PATH):
        return {"api_keys": {}, "targets": []}
    try:
        with open(DB_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return {"api_keys": {}, "targets": []}

def save_db(data):
    """Saves the configuration database."""
    try:
        with open(DB_PATH, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        CONSOLE.print(f"[bold red]Error saving database:[/bold red] {e}")

def validate_input(target):
    """
    Performs real validation for Email, IP, or Domain.
    Returns the type and the cleaned target, or None.
    """
    if "@" in target and "." in target:
        return "email", target.lower()
    
    # Simple IP validation
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        try:
            parts = [int(x) for x in target.split('.')]
            if all(0 <= x <= 255 for x in parts):
                return "ip", target
        except ValueError:
            pass
    
    # Simple Domain validation
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
        return "domain", target.lower()
        
    return None, None

# --- Core Intelligence Modules (Real Implementation) ---

def ip_lookup(ip_address):
    """
    Performs real IP geolocation using ip-api.com (HTTPS).
    Returns a dictionary of results or None on failure.
    """
    CONSOLE.print(f"[bold yellow]Performing real IP Geolocation for {ip_address}...[/bold yellow]")
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "success":
            return data
        else:
            CONSOLE.print(f"[bold red]IP API Error:[/bold red] {data.get('message', 'Unknown error')}")
            return None
    except requests.exceptions.RequestException as e:
        CONSOLE.print(f"[bold red]Network Error during IP Lookup:[/bold red] {e}")
        return None

def whois_lookup(domain):
    """
    Performs real WHOIS lookup for a domain.
    Returns a dictionary of results or None on failure.
    """
    CONSOLE.print(f"[bold yellow]Performing real WHOIS Lookup for {domain}...[/bold yellow]")
    try:
        w = whois.whois(domain)
        # whois library returns a WhoisEntry object, which can be converted to dict
        # or we can return the raw text for comprehensive data
        if w.text and "No match for" in w.text:
            CONSOLE.print("[bold red]WHOIS Error:[/bold red] No match found for this domain.")
            return None
        
        # Return a dictionary of key WHOIS fields
        result = {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "emails": w.emails,
            "status": w.status
        }
        # Clean up None values and lists
        for key, value in result.items():
            if isinstance(value, list):
                result[key] = ", ".join(map(str, value))
            elif value is None:
                result[key] = "N/A"
        
        return result
    except Exception as e:
        CONSOLE.print(f"[bold red]WHOIS Error:[/bold red] {e}")
        return None

def dns_lookup(domain):
    """
    Performs real DNS record lookup (A, MX, NS, TXT) using dnspython.
    Returns a dictionary of results.
    """
    CONSOLE.print(f"[bold yellow]Performing real DNS Lookup for {domain}...[/bold yellow]")
    results = {}
    record_types = ['A', 'MX', 'NS', 'TXT']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=2.0) # Added timeout
            results[record_type] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = ["No Answer"]
        except dns.resolver.NXDOMAIN:
            results[record_type] = ["Domain Not Found"]
            break
        except Exception as e:
            results[record_type] = [f"Error: {e}"]
    
    return results

# --- Offensive Intelligence Modules (Real Implementation) ---

def subdomain_enumeration(domain):
    """
    Finds subdomains using crt.sh API.
    Returns a list of subdomains.
    """
    CONSOLE.print(f"[bold yellow]Enumerating subdomains for {domain}...[/bold yellow]")
    subdomains = set()
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        response.raise_for_status()
        data = response.json()
        for entry in data:
            subdomains.add(entry["name_value"].lower())
        return list(subdomains)
    except requests.exceptions.RequestException as e:
        CONSOLE.print(f"[bold red]Network Error during Subdomain Enumeration:[/bold red] {e}")
        return []
    except json.JSONDecodeError:
        CONSOLE.print("[bold red]Error decoding JSON from crt.sh.[/bold red]")
        return []

def vulnerability_mapping(service_name):
    """
    Searches for vulnerabilities for a given service name (e.g., "Apache 2.4.41") using Vulners API.
    Returns a dictionary of vulnerabilities.
    """
    CONSOLE.print(f"[bold yellow]Mapping vulnerabilities for {service_name}...[/bold yellow]")
    api_url = "https://vulners.com/api/v3/search/lucene/"
    payload = {
        "query": f"bulletin_type:exploit AND (title:\"{service_name}\" OR description:\"{service_name}\")",
        "size": 5
    }
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("result") == "OK" and data["data"]["total"] > 0:
            exploits = []
            for exploit in data["data"]["search"]:
                exploits.append({
                    "id": exploit["_id"],
                    "title": exploit["_source"]["title"],
                    "cvss_score": exploit["_source"].get("cvss", {}).get("score", "N/A")
                })
            return {"vulnerabilities": exploits}
        else:
            return {"vulnerabilities": "No public exploits found."}
    except requests.exceptions.RequestException as e:
        CONSOLE.print(f"[bold red]Network Error during Vulnerability Mapping:[/bold red] {e}")
        return None
    except Exception as e:
        CONSOLE.print(f"[bold red]Error with Vulners API:[/bold red] {e}")
        return None

# --- Main Application Logic ---

def generate_pdf_report(target, results, report_type):
    """Generates a PDF report for the investigation."""
    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, txt=f"SRO REPORT - {report_type.upper()}", ln=True, align='C')
        pdf.set_font("Arial", size=10)
        
        # Convert results to a readable string format for PDF
        report_content = json.dumps(results, indent=4)
        
        # FPDF does not handle complex Unicode well, so we encode/decode to clean it
        clean_content = report_content.encode('latin-1', 'replace').decode('latin-1')
        
        pdf.multi_cell(0, 5, txt=clean_content)
        
        report_dir = os.path.join(DATA_DIR, "Reports")
        if not os.path.exists(report_dir): os.makedirs(report_dir)
        
        filename = f"{report_type.replace(' ', '_')}_{target.replace('.', '_')}_{int(time.time())}.pdf"
        full_path = os.path.join(report_dir, filename)
        pdf.output(full_path)
        CONSOLE.print(f"[bold green]PDF Report saved to:[/bold green] {full_path}")
        return full_path
    except Exception as e:
        CONSOLE.print(f"[bold red]Error generating PDF report:[/bold red] {e}")
        return None

def generate_json_report(target, results, report_type):
    """Generates a JSON report for the investigation."""
    try:
        report_dir = os.path.join(DATA_DIR, "Reports")
        if not os.path.exists(report_dir): os.makedirs(report_dir)
        
        filename = f"{report_type.replace(' ', '_')}_{target.replace('.', '_')}_{int(time.time())}.json"
        full_path = os.path.join(report_dir, filename)
        
        with open(full_path, 'w') as f:
            json.dump(results, f, indent=4)
            
        CONSOLE.print(f"[bold green]JSON Report saved to:[/bold green] {full_path}")
        return full_path
    except Exception as e:
        CONSOLE.print(f"[bold red]Error generating JSON report:[/bold red] {e}")
        return None

def display_results(title, data):
    """Displays results in a structured Rich table."""
    if not data:
        CONSOLE.print(f"[bold red]No results found for {title}.[/bold red]")
        return

    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                value = "\n".join(value)
            table.add_row(str(key), str(value))
    elif isinstance(data, str):
        # For raw text data
        table.add_row("Raw Data", data)
    
    CONSOLE.print(Panel(table, border_style="blue"))

def single_investigation():
    """Handles a single, real-time investigation."""
    target = CONSOLE.input("[bold cyan]Enter Target (Email, IP, or Domain):[/bold cyan] ").strip()
    target_type, cleaned_target = validate_input(target)

    if not cleaned_target:
        CONSOLE.print("[bold red]Invalid input. Please enter a valid Email, IP, or Domain.[/bold red]")
        return

    CONSOLE.print(f"\n[bold green]Starting Real Investigation for {cleaned_target} ({target_type})...[/bold green]")

    results = {}

    if target_type == "ip":
        results['IP Geolocation'] = ip_lookup(cleaned_target)
        # Simulate service detection for vulnerability mapping
        results['Vulnerability Mapping (Simulated)'] = vulnerability_mapping("Apache 2.4.41")
    elif target_type == "domain":
        results['WHOIS'] = whois_lookup(cleaned_target)
        results['DNS Records'] = dns_lookup(cleaned_target)
        results['Subdomain Enumeration'] = subdomain_enumeration(cleaned_target)
    
    # Display results
    for title, data in results.items():
        display_results(title, data)
        
    # Generate reports
    report_data = {
        "target": cleaned_target,
        "type": target_type,
        "timestamp": time.time(),
        "results": results
    }
    
    generate_json_report(cleaned_target, report_data, "Single_Investigation")
    generate_pdf_report(cleaned_target, report_data, "Single_Investigation")

def main_menu():
    """Displays the main menu."""
    CONSOLE.print(Panel("[bold yellow]SRO v2.0 - Strategic Reconnaissance Operations[/bold yellow]", border_style="green"))
    
    menu = Table(title="Main Menu", show_header=True, header_style="bold cyan")
    menu.add_column("ID", style="dim")
    menu.add_column("Operation", style="bold white")
    
    menu.add_row("1", "Single Real-Time Investigation (IP/Domain)")
    menu.add_row("2", "Full Strategic Investigation (Not Implemented Yet)")
    menu.add_row("3", "Settings & API Keys")
    menu.add_row("4", "Exit")
    
    CONSOLE.print(menu)

def settings_menu():
    """Handles API key configuration."""
    db = load_db()
    CONSOLE.print(Panel("[bold yellow]Settings & API Keys[/bold yellow]", border_style="yellow"))
    
    # Example API key setup (will be expanded)
    api_keys = db.get("api_keys", {})
    
    CONSOLE.print("\n[bold cyan]Current API Keys:[/bold cyan]")
    for key, value in api_keys.items():
        status = "[bold green]Configured[/bold green]" if value else "[bold red]Missing[/bold red]"
        CONSOLE.print(f"- {key}: {status}")
        
    key_name = CONSOLE.input("\n[bold cyan]Enter API Key Name to Configure (e.g., shodan, telegram) or 'back':[/bold cyan] ").strip().lower()
    
    if key_name == 'back':
        return
        
    key_value = CONSOLE.input(f"[bold cyan]Enter value for {key_name}:[/bold cyan] ").strip()
    
    db["api_keys"][key_name] = key_value
    save_db(db)
    CONSOLE.print(f"[bold green]API Key for {key_name} saved successfully.[/bold green]")

def main():
    """Main entry point of the application."""
    try:
        while True:
            main_menu()
            choice = CONSOLE.input("[bold cyan]Enter your choice:[/bold cyan] ").strip()
            
            if choice == '1':
                single_investigation()
            elif choice == '2':
                CONSOLE.print("[bold red]Full Strategic Investigation is not yet implemented. Please use option 1.[/bold red]")
            elif choice == '3':
                settings_menu()
            elif choice == '4':
                CONSOLE.print("[bold green]Exiting SRO. Stay safe.[/bold green]")
                sys.exit(0)
            else:
                CONSOLE.print("[bold red]Invalid choice. Please try again.[/bold red]")
            
            CONSOLE.input("\n[bold dim]Press Enter to continue...[/bold dim]")
    except KeyboardInterrupt:
        CONSOLE.print("\n[bold green]Exiting SRO. Stay safe.[/bold green]")
        sys.exit(0)

if __name__ == "__main__":
    main()
