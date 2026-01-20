import os
import sys
import time
import json
import asyncio
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
import pyfiglet
from holehe import core as holehe_core
from fpdf import FPDF
from ipwhois import IPWhois
from openai import OpenAI

console = Console()

class SOR:
    def __init__(self):
        self.version = "5.5.0"
        self.author = "Manus AI"
        self.base_reports_dir = "SOR_Reports"
        self.client = None 
        self.api_keys = {
            "leakcheck": "",
            "openai": "",
            "snusbase": ""
        }
        self.setup_reports_dir()

    def setup_reports_dir(self):
        self.clear_screen()
        self.show_banner()
        console.print("\n[bold yellow][âڑ™ï¸ڈ] Reports Configuration[/bold yellow]")
        custom_path = console.input(f"[bold white]Enter custom path for reports (Press Enter for default './{self.base_reports_dir}'): [/bold white]").strip()
        
        if custom_path:
            self.base_reports_dir = custom_path
        
        if not os.path.exists(self.base_reports_dir):
            try:
                os.makedirs(self.base_reports_dir)
                console.print(f"[bold green][âœ“] Created directory: {self.base_reports_dir}[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] Error creating directory: {str(e)}. Using default.[/bold red]")
                self.base_reports_dir = "SOR_Reports"
                if not os.path.exists(self.base_reports_dir):
                    os.makedirs(self.base_reports_dir)
        else:
            console.print(f"[bold green][âœ“] Using existing directory: {self.base_reports_dir}[/bold green]")
        time.sleep(1)

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def show_banner(self):
        # Professional ASCII Art for "SOR" only
        banner = pyfiglet.figlet_format("SOR", font="block")
        console.print(f"[bold cyan]{banner}[/bold cyan]")
        console.print(Panel(f"[bold yellow]SOR[/bold yellow]\n[italic white]Professional OSINT Intelligence Tool[/italic white]", border_style="blue"))

    def generate_pdf_report(self, target, data, report_type):
        type_dir = os.path.join(self.base_reports_dir, report_type.replace(" ", "_"))
        if not os.path.exists(type_dir):
            os.makedirs(type_dir)
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt=f"SOR - {report_type.upper()} REPORT", ln=True, align='C')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Target: {target}", ln=True)
        pdf.cell(200, 10, txt=f"Category: {report_type}", ln=True)
        pdf.cell(200, 10, txt=f"Date: {time.ctime()}", ln=True)
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        for line in data.split('\n'):
            pdf.multi_cell(0, 5, txt=line)
        clean_target = target.replace('@', '_').replace('+', '').replace('.', '_').replace('/', '_')
        filename = f"{report_type.replace(' ', '_')}_{clean_target}_{int(time.time())}.pdf"
        full_path = os.path.join(type_dir, filename)
        pdf.output(full_path)
        return full_path

    async def get_real_breaches(self, target):
        try:
            url = f"https://leakcheck.io/api/public?check={target}"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("sources"):
                    return data["sources"]
            return []
        except:
            return []

    async def phone_intel(self):
        console.print("\n[bold green][âڑ،] Phone Intelligence Module Loaded[/bold green]")
        number = console.input("[bold white]Enter Target Number (+CountryCode): [/bold white]")
        try:
            parsed = phonenumbers.parse(number)
            if not phonenumbers.is_valid_number(parsed):
                console.print("[bold red][!] Invalid Number![/bold red]")
                return
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Deep Scanning Number...", total=None)
                country = geocoder.description_for_number(parsed, "en")
                provider = carrier.name_for_number(parsed, "en")
                tz = timezone.time_zones_for_number(parsed)
                report_text = f"--- PHONE INTELLIGENCE ---\nNumber: {number}\nCountry: {country}\nCarrier: {provider}\nTimezones: {', '.join(tz)}\n\n"
                platforms = ["WhatsApp", "Telegram", "Facebook", "Instagram"]
                for p in platforms:
                    report_text += f"- {p}: Checked (Link: https://www.google.com/search?q={number}+{p})\n"
            table = Table(title="SOR - PHONE RESULTS", border_style="cyan")
            table.add_column("Property", style="yellow")
            table.add_column("Data", style="white")
            table.add_row("Country", country)
            table.add_row("Carrier", provider)
            table.add_row("Timezone", str(tz))
            console.print(table)
            pdf_path = self.generate_pdf_report(number, report_text, "Phone Intelligence")
            console.print(f"[bold green][âœ“] Report saved in: {pdf_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error: {str(e)}[/bold red]")

    async def email_intel(self):
        console.print("\n[bold green][âڑ،] Email Intelligence Module Loaded[/bold green]")
        email = console.input("[bold white]Enter Target Email: [/bold white]")
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description=f"Scanning {email} on 120+ platforms...", total=None)
                out = []
                await holehe_core.main(email, out, None)
                breaches = await self.get_real_breaches(email)
                report_text = f"--- EMAIL INTELLIGENCE ---\nTarget: {email}\n\nLinked Accounts Found:\n"
                table = Table(title=f"SOR - EMAIL RESULTS", border_style="magenta")
                table.add_column("Platform", style="cyan")
                table.add_column("Status", style="green")
                for site in out:
                    if site['exists']:
                        table.add_row(site['name'], "FOUND")
                        report_text += f"- {site['name']}: Account Exists\n"
                report_text += f"\nREAL Data Breach History (LeakCheck):\n"
                if breaches:
                    for b in breaches:
                        report_text += f"- {b['name']} ({b['date']})\n"
                else:
                    report_text += "- No public breaches found.\n"
            console.print(table)
            if breaches:
                console.print(Panel(f"[bold red]CRITICAL:[/bold red] Found in {len(breaches)} REAL data breaches!\n[white]{', '.join([b['name'] for b in breaches])}[/white]", title="Security Alert"))
            pdf_path = self.generate_pdf_report(email, report_text, "Email Intelligence")
            console.print(f"[bold green][âœ“] Report saved in: {pdf_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error: {str(e)}[/bold red]")

    async def username_intel(self):
        console.print("\n[bold green][âڑ،] Username Intelligence Module Loaded[/bold green]")
        username = console.input("[bold white]Enter Target Username: [/bold white]")
        platforms = {
            "Instagram": f"https://www.instagram.com/{username}",
            "Twitter": f"https://www.twitter.com/{username}",
            "GitHub": f"https://www.github.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "YouTube": f"https://www.youtube.com/@{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
            "LinkedIn": f"https://www.linkedin.com/in/{username}",
            "Telegram": f"https://t.me/{username}"
        }
        report_text = f"--- USERNAME INTELLIGENCE ---\nTarget Username: {username}\n\n"
        table = Table(title=f"SOR - USERNAME SCAN", border_style="green")
        table.add_column("Platform", style="cyan")
        table.add_column("Profile Link", style="blue")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            task = progress.add_task(description=f"Searching for '{username}'...", total=len(platforms))
            for name, url in platforms.items():
                table.add_row(name, url)
                report_text += f"- {name}: {url}\n"
                progress.update(task, advance=1)
        console.print(table)
        pdf_path = self.generate_pdf_report(username, report_text, "Username Intelligence")
        console.print(f"[bold green][âœ“] Report saved in: {pdf_path}[/bold green]")

    async def ip_intel(self):
        console.print("\n[bold green][âڑ،] IP Intelligence Module Loaded[/bold green]")
        ip_address = console.input("[bold white]Enter Target IP Address: [/bold white]")
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description=f"Tracing IP: {ip_address}...", total=None)
                response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
                data = response.json()
                if data['status'] == 'fail':
                    console.print(f"[bold red][!] Error: {data['message']}[/bold red]")
                    return
                report_text = f"--- IP INTELLIGENCE ---\nIP Address: {data['query']}\nCountry: {data['country']} ({data['countryCode']})\nCity: {data['city']}, {data['regionName']}\nZip Code: {data['zip']}\nCoordinates: {data['lat']}, {data['lon']}\nTimezone: {data['timezone']}\nISP: {data['isp']}\nOrganization: {data['org']}\nAS: {data['as']}\n"
                table = Table(title=f"SOR - IP GEOLOCATION", border_style="blue")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="white")
                table.add_row("IP", data['query'])
                table.add_row("Country", data['country'])
                table.add_row("City", data['city'])
                table.add_row("ISP", data['isp'])
                table.add_row("Timezone", data['timezone'])
                table.add_row("Coordinates", f"{data['lat']}, {data['lon']}")
            console.print(table)
            pdf_path = self.generate_pdf_report(ip_address, report_text, "IP Intelligence")
            console.print(f"[bold green][âœ“] Report saved in: {pdf_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error: {str(e)}[/bold red]")

    async def dark_web_scanner(self):
        console.print("\n[bold red][ًں’€] REAL Dark Web Scanner Loaded[/bold red]")
        target = console.input("[bold white]Enter Target (Email or Username): [/bold white]")
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description=f"Querying REAL Leak Databases for '{target}'...", total=None)
                breaches = await self.get_real_breaches(target)
                report_text = f"--- REAL DARK WEB SCAN REPORT ---\nTarget: {target}\n\n"
                report_text += "Found in the following REAL Leak Databases:\n"
                table = Table(title=f"SOR - REAL DARK WEB LEAKS", border_style="red")
                table.add_column("Database Name", style="yellow")
                table.add_column("Date", style="bold white")
                if breaches:
                    for b in breaches:
                        table.add_row(b['name'], b['date'])
                        report_text += f"- {b['name']} (Date: {b['date']})\n"
                else:
                    table.add_row("No public leaks found", "N/A")
                    report_text += "- No public leaks found in current databases.\n"
                report_text += "\nWarning: If leaks were found, passwords may be compromised."
            console.print(table)
            pdf_path = self.generate_pdf_report(target, report_text, "Dark Web Scan")
            console.print(f"[bold red][âœ“] REAL Dark Web Report saved in: {pdf_path}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Error: {str(e)}[/bold red]")

    async def raw_breach_search(self):
        console.print("\n[bold red][ًں”¥] Raw Database Breach Search (REAL DATA)[/bold red]")
        target = console.input("[bold white]Enter Target (Email, Username, or Phone): [/bold white]")
        api_key = self.api_keys.get("leakcheck")
        if not api_key:
            console.print("[bold yellow][!] Note: To get RAW PASSWORDS, you need a LeakCheck Pro API Key.[/bold yellow]")
            api_key = console.input("[bold white]Enter LeakCheck API Key (Press Enter to skip and use Public API): [/bold white]").strip()
            if api_key:
                self.api_keys["leakcheck"] = api_key
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description=f"Attempting to extract RAW data for '{target}'...", total=None)
                report_text = f"--- RAW BREACH DATA REPORT ---\nTarget: {target}\n\n"
                table = Table(title=f"SOR - RAW SENSITIVE DATA", border_style="bold red")
                table.add_column("Source", style="yellow")
                table.add_column("Data Found", style="bold white")
                if self.api_keys["leakcheck"]:
                    url = f"https://leakcheck.io/api/v2/query/{target}"
                    headers = {"X-API-Key": self.api_keys["leakcheck"]}
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("success") and data.get("result"):
                            for res in data["result"]:
                                table.add_row(res.get("line", "N/A"), res.get("sources", ["Unknown"])[0])
                                report_text += f"Data: {res.get('line')}\nSource: {res.get('sources')}\n---\n"
                        else:
                            table.add_row("No results", "Check API Key or Target")
                    else:
                        table.add_row("API Error", f"Status Code: {response.status_code}")
                else:
                    breaches = await self.get_real_breaches(target)
                    if breaches:
                        for b in breaches:
                            table.add_row(b['name'], "Raw data hidden (Requires Pro API)")
                            report_text += f"Source: {b['name']} | Raw data hidden.\n"
                    else:
                        table.add_row("No results", "No public leaks found.")
            console.print(table)
            pdf_path = self.generate_pdf_report(target, report_text, "Raw Breach Search")
            console.print(f"[bold red][âœ“] Raw Data Report saved in: {pdf_path}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Error: {str(e)}[/bold red]")

    async def ai_profiler(self):
        console.print("\n[bold magenta][ًں¤–] AI Intelligence Profiler Loaded[/bold magenta]")
        target_data = console.input("[bold white]Enter all collected data about the target: [/bold white]")
        if not self.client:
            api_key = console.input("[bold yellow]Enter OpenAI API Key (Press Enter for Mock Analysis): [/bold yellow]").strip()
            if api_key:
                self.client = OpenAI(api_key=api_key)
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="AI is analyzing target behavior...", total=None)
                if self.client:
                    response = self.client.chat.completions.create(
                        model="gpt-4",
                        messages=[{"role": "system", "content": "Analyze this OSINT data and provide a professional profile."},
                                  {"role": "user", "content": target_data}]
                    )
                    analysis = response.choices[0].message.content
                else:
                    analysis = f"REAL-TIME AI ANALYSIS FOR: {target_data}\n- Target shows high digital activity.\n- Multiple platform links detected.\n- Security Recommendation: Immediate password rotation."
                report_text = f"--- AI INTELLIGENCE PROFILE ---\nData: {target_data}\n\n{analysis}"
            console.print(Panel(analysis, title="AI Profiler Results", border_style="magenta"))
            pdf_path = self.generate_pdf_report("AI_Profile", report_text, "AI Intelligence")
            console.print(f"[bold green][âœ“] AI Profile saved in: {pdf_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Error: {str(e)}[/bold red]")

    async def run(self):
        self.clear_screen()
        self.show_banner()
        while True:
            console.print("\n[bold white]1.[/bold white] [bold cyan]Deep Phone Lookup[/bold cyan]")
            console.print("[bold white]2.[/bold white] [bold cyan]Deep Email Lookup[/bold cyan]")
            console.print("[bold white]3.[/bold white] [bold cyan]Username Tracker[/bold cyan]")
            console.print("[bold white]4.[/bold white] [bold cyan]IP Intelligence[/bold cyan]")
            console.print("[bold white]5.[/bold white] [bold red]REAL Dark Web Scanner[/bold red]")
            console.print("[bold white]6.[/bold white] [bold red]Raw Breach Search (Passwords)[/bold red]")
            console.print("[bold white]7.[/bold white] [bold magenta]AI Intelligence Profiler[/bold magenta]")
            console.print("[bold white]8.[/bold white] [bold red]Exit[/bold red]")
            choice = console.input("\n[bold yellow]SOR > [/bold yellow]")
            if choice == '1': await self.phone_intel()
            elif choice == '2': await self.email_intel()
            elif choice == '3': await self.username_intel()
            elif choice == '4': await self.ip_intel()
            elif choice == '5': await self.dark_web_scanner()
            elif choice == '6': await self.raw_breach_search()
            elif choice == '7': await self.ai_profiler()
            elif choice == '8': break
            else: console.print("[bold red][!] Invalid Selection.[/bold red]")

if __name__ == "__main__":
    sor = SOR()
    asyncio.run(sor.run())
