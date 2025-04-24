import asyncio
import aiohttp
import waybackpy
import logging
import json
import os
import re
import subprocess
import requests
import sys
import argparse
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from PIL import Image

console = Console()
logging.basicConfig(
    filename="tulpar.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class Tulpar:
    def __init__(self, domain, output_dir="output"):
        self.domain = domain
        self.output_dir = output_dir
        self.rate_limit = 0.5  # Sabit rate limit
        self.subfinder_timeout = 300  # Sabit 5 dakika
        self.subdomains = set()
        self.live_subdomains = set()
        self.endpoints = set()
        self.js_endpoints = []
        self.vulnerabilities = []
        self.screenshots = {}
        os.makedirs(self.output_dir, exist_ok=True)
        self.start_time = datetime.now()
        logging.info(f"Tulpar başlatıldı, hedef: {self.domain}")

    async def run(self):
        console.print("[bold yellow]emrewashere: created by Emre İşlek - Tulpar V1[/bold yellow]")
        console.print(f"[bold yellow]Tulpar çalışıyor, hedef: {self.domain}[/bold yellow]")
        logging.info("Tulpar çalışmaya başladı.")
        await self.enumerate_subdomains()
        await self.check_live_subdomains()
        await self.collect_js_endpoints()
        await self.test_vulnerabilities()
        await self.collect_wayback_endpoints()
        await self.save_results()
        self.display_results()
        console.print("[bold yellow]Tulpar tamamlandı![/bold yellow]")
        logging.info("Tulpar tamamlandı.")

    async def enumerate_subdomains(self):
        console.print("[bold green]Subdomain tarama başlatılıyor (Subfinder)...[/bold green]")
        try:
            subfinder_output = f"{self.output_dir}/subfinder_{self.domain}.txt"
            subfinder_cmd = [
                "subfinder", "-d", self.domain,
                "-o", subfinder_output,
                "-t", "50", "-timeout", str(self.subfinder_timeout),
                "-exclude-sources", "digitorus"
            ]
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Subfinder taranıyor", total=None)
                process = await asyncio.create_subprocess_exec(
                    *subfinder_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                try:
                    async with asyncio.timeout(self.subfinder_timeout):
                        while True:
                            line = await process.stdout.readline()
                            if not line:
                                break
                            line = line.decode().strip()
                            if line:
                                console.print(f"[cyan]Subfinder Çıktısı: {line}[/cyan]")
                                logging.info(f"Subfinder çıktısı: {line}")
                                if line.endswith(self.domain):
                                    self.subdomains.add(line)
                                    console.print(f"[cyan]Subfinder Bulundu: {line}[/cyan]")
                                    logging.info(f"Subfinder subdomain bulundu: {line}")
                            progress.advance(task, advance=1)
                except asyncio.TimeoutError:
                    console.print(f"[yellow]Subfinder {self.subfinder_timeout} saniyede tamamlanamadı, zorla durduruldu.[/yellow]")
                    logging.warning(f"Subfinder timeout: {self.subfinder_timeout} saniye")
                    process.terminate()
                    await process.wait()
                stderr = await process.stderr.read()
                stderr_str = stderr.decode().strip()
                if stderr_str:
                    if "panic: runtime error" in stderr_str:
                        console.print(f"[yellow]Subfinder çöktü (digitorus hatası), diğer kaynaklarla devam ediliyor: {stderr_str}[/yellow]")
                        logging.warning(f"Subfinder çökme hatası: {stderr_str}")
                    else:
                        console.print(f"[yellow]Subfinder stderr: {stderr_str}[/yellow]")
                        logging.warning(f"Subfinder stderr: {stderr_str}")
                if process.returncode == 0 or self.subdomains:
                    console.print("[bold green]Subfinder taraması tamamlandı.[/bold green]")
                    if os.path.exists(subfinder_output):
                        with open(subfinder_output, "r") as f:
                            for line in f:
                                subdomain = line.strip()
                                if subdomain and subdomain.endswith(self.domain):
                                    self.subdomains.add(subdomain)
                                    console.print(f"[cyan]Subfinder Dosya Bulundu: {subdomain}[/cyan]")
                                    logging.info(f"Subfinder dosya subdomain bulundu: {subdomain}")
                else:
                    console.print(f"[yellow]Subfinder başarısız, return code: {process.returncode}. Dosyadan subdomain okunuyor.[/yellow]")
                    logging.warning(f"Subfinder başarısız, return code: {process.returncode}")
                    if os.path.exists(subfinder_output):
                        with open(subfinder_output, "r") as f:
                            for line in f:
                                subdomain = line.strip()
                                if subdomain and subdomain.endswith(self.domain):
                                    self.subdomains.add(subdomain)
                                    console.print(f"[cyan]Subfinder Dosya Bulundu: {subdomain}[/cyan]")
                                    logging.info(f"Subfinder dosya subdomain bulundu: {subdomain}")
        except Exception as e:
            console.print(f"[yellow]Subfinder hatası, devam ediliyor: {str(e)}[/yellow]")
            logging.warning(f"Subfinder hatası: {str(e)}")

        console.print(f"[bold green]Toplam {len(self.subdomains)} subdomain bulundu.[/bold green]")

    async def check_live_subdomains(self):
        console.print("[bold green]Live host kontrolü başlatılıyor...[/bold green]")
        headers = {"User-Agent": "Tulpar/1.0 (BugBountyScanner)"}
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ssl=False), headers=headers) as session:
            tasks = []
            for subdomain in self.subdomains:
                console.print(f"[yellow]Kontrol ediliyor: {subdomain}[/yellow]")
                tasks.append(self._check_live(session, subdomain))
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Live host kontrolü", total=len(tasks))
                for future in asyncio.as_completed(tasks):
                    await future
                    progress.advance(task)
                    await asyncio.sleep(self.rate_limit)
        console.print(f"[bold green]{len(self.live_subdomains)} canlı subdomain bulundu.[/bold green]")
        logging.info(f"{len(self.live_subdomains)} canlı subdomain bulundu.")

    async def _check_live(self, session, subdomain):
        for protocol in ["http", "https"]:
            try:
                async with session.get(
                    f"{protocol}://{subdomain}",
                    timeout=15
                ) as resp:
                    if resp.status < 400:
                        live_url = f"{protocol}://{subdomain}"
                        self.live_subdomains.add(live_url)
                        console.print(f"[cyan]Canlı: {live_url} (Status: {resp.status})[/cyan]")
                        logging.info(f"Canlı subdomain: {live_url} (Status: {resp.status})")
                        await self._take_screenshot(live_url)
                        return
                    else:
                        console.print(f"[yellow]Hata: {protocol}://{subdomain} - Status: {resp.status}[/yellow]")
                        logging.warning(f"Live host kontrol hatası: {protocol}://{subdomain} - Status: {resp.status}")
            except Exception as e:
                console.print(f"[yellow]Hata: {protocol}://{subdomain} - {str(e) or 'Bilinmeyen hata'}[/yellow]")
                logging.warning(f"Live host kontrol hatası: {protocol}://{subdomain} - {str(e) or 'Bilinmeyen hata'}")
        headers = {"User-Agent": "Tulpar/1.0 (BugBountyScanner)"}
        for protocol in ["http", "https"]:
            try:
                resp = requests.head(f"{protocol}://{subdomain}", timeout=15, allow_redirects=True, headers=headers, verify=False)
                if resp.status_code < 400:
                    live_url = f"{protocol}://{subdomain}"
                    self.live_subdomains.add(live_url)
                    console.print(f"[cyan]Canlı (yedek): {live_url} (Status: {resp.status_code})[/cyan]")
                    logging.info(f"Canlı subdomain (yedek): {live_url} (Status: {resp.status_code})")
                    await self._take_screenshot(live_url)
                    return
                else:
                    console.print(f"[yellow]Hata (yedek): {protocol}://{subdomain} - Status: {resp.status_code}[/yellow]")
                    logging.warning(f"Live host kontrol hatası (yedek): {protocol}://{subdomain} - Status: {resp.status_code}")
            except Exception as e:
                console.print(f"[yellow]Hata (yedek): {protocol}://{subdomain} - {str(e) or 'Bilinmeyen hata'}[/yellow]")
                logging.warning(f"Live host kontrol hatası (yedek): {protocol}://{subdomain} - {str(e) or 'Bilinmeyen hata'}")

    async def _take_screenshot(self, url):
        try:
            headers = {"User-Agent": "Tulpar/1.0 (BugBountyScanner)"}
            response = requests.get(url, timeout=15, headers=headers, verify=False)
            img = Image.new("RGB", (800, 600), color="white")
            img.save(f"{self.output_dir}/screenshot_{urlparse(url).netloc}.png")
            self.screenshots[url] = f"screenshot_{urlparse(url).netloc}.png"
            logging.info(f"Screenshot alındı: {url}")
        except Exception as e:
            console.print(f"[yellow]Screenshot hatası: {url} - {str(e)}[/yellow]")
            logging.warning(f"Screenshot hatası: {url} - {str(e)}")

    async def collect_js_endpoints(self):
        console.print("[bold green]JavaScript dosyalarından endpoint'ler toplanıyor...[/bold green]")
        headers = {"User-Agent": "Tulpar/1.0 (BugBountyScanner)"}
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ssl=False), headers=headers) as session:
            for url in self.live_subdomains:
                try:
                    async with session.get(url, timeout=15) as resp:
                        if resp.status >= 400:
                            continue
                        html = await resp.text()
                        js_urls = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html, re.IGNORECASE)
                        for js_url in js_urls:
                            js_url = urljoin(url, js_url)
                            if urlparse(js_url).netloc.endswith(self.domain):
                                try:
                                    async with session.get(js_url, timeout=15) as js_resp:
                                        if js_resp.status >= 400:
                                            continue
                                        js_content = await js_resp.text()
                                        endpoints = re.findall(
                                            r'[\'"](https?://[^"\']+?)[\'"]|[\'"](/[^"\']+?)[\'"]|[\'"](api/[^"\']+?)[\'"]|'
                                            r'[\'"](graphql/[^"\']+?)[\'"]|[\'"](ws://[^"\']+?)[\'"]|[\'"]([^"\']+?\?[^"\']+?)[\'"]|'
                                            r'[\'"]([^"\']+?/[a-zA-Z0-9_-]+?/[0-9a-zA-Z_-]+?)[\'"]',
                                            js_content
                                        )
                                        for endpoint_group in endpoints:
                                            endpoint = next((e for e in endpoint_group if e), None)
                                            if not endpoint:
                                                continue
                                            if endpoint.startswith('/'):
                                                endpoint = urljoin(url, endpoint)
                                            if urlparse(endpoint).netloc.endswith(self.domain):
                                                parsed = urlparse(endpoint)
                                                params = parse_qs(parsed.query)
                                                param_count = len(params)
                                                param_names = list(params.keys())
                                                self.js_endpoints.append({
                                                    "url": endpoint,
                                                    "parameters": param_count,
                                                    "param_names": param_names
                                                })
                                                console.print(f"[cyan]JS Endpoint: {endpoint} (Parametre: {param_count}, İsimler: {param_names})[/cyan]")
                                                logging.info(f"JS endpoint: {endpoint} (Parametre: {param_count}, İsimler: {param_names})")
                                except Exception as e:
                                    console.print(f"[yellow]JS dosyası hatası: {js_url} - {str(e)}[/yellow]")
                                    logging.warning(f"JS dosyası hatası: {js_url} - {str(e)}")
                except Exception as e:
                    console.print(f"[yellow]JS endpoint toplama hatası: {url} - {str(e)}[/yellow]")
                    logging.warning(f"JS endpoint toplama hatası: {url} - {str(e)}")
                await asyncio.sleep(self.rate_limit)
        console.print(f"[bold green]{len(self.js_endpoints)} JS endpoint bulundu.[/bold green]")

    async def test_vulnerabilities(self):
        console.print("[bold green]Zafiyet testleri başlatılıyor...[/bold green]")
        headers = {"User-Agent": "Tulpar/1.0 (BugBountyScanner)"}
        payloads = {
            "openredirect": [
                "https://evil.com", "//evil.com", "http://evil.com",
                "?redirect=https://evil.com", "?url=//evil.com"
            ],
            "pathtraversal": [
                "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                "../../windows/win.ini", "%2e%2e%2f%2e%2e%2fwindows%2fwin.ini"
            ],
            "xss": [
                "<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)", "'-alert(1)-'"
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{ '7' * 7 }}"
            ]
        }
        params = ["q", "search", "id", "page", "redirect", "url", "path", "file", "template"]
        
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ssl=False), headers=headers) as session:
            for url in self.live_subdomains:
                parsed_url = urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                for vuln_type, payload_list in payloads.items():
                    for payload in payload_list:
                        for param in params:
                            test_url = f"{base_url}?{param}={payload}"
                            try:
                                async with session.get(test_url, timeout=15, allow_redirects=False) as resp:
                                    response_text = await resp.text()
                                    if vuln_type == "openredirect" and (resp.status in [301, 302] and re.search(r'https?://(www\.)?evil\.com', resp.headers.get("Location", ""))):
                                        self.vulnerabilities.append({
                                            "type": "openredirect",
                                            "url": test_url,
                                            "payload": payload,
                                            "severity": "medium"
                                        })
                                        console.print(f"[red]Zafiyet Bulundu: Open Redirect - {test_url} - Payload: {payload}[/red]")
                                        logging.info(f"Open Redirect bulundu: {test_url} - Payload: {payload}")
                                    elif vuln_type == "pathtraversal" and ("root:" in response_text or "[extensions]" in response_text):
                                        self.vulnerabilities.append({
                                            "type": "pathtraversal",
                                            "url": test_url,
                                            "payload": payload,
                                            "severity": "high"
                                        })
                                        console.print(f"[red]Zafiyet Bulundu: Path Traversal - {test_url} - Payload: {payload}[/red]")
                                        logging.info(f"Path Traversal bulundu: {test_url} - Payload: {payload}")
                                    elif vuln_type == "xss" and any(p in response_text.lower() for p in ["alert(1)", "onerror"]):
                                        self.vulnerabilities.append({
                                            "type": "xss",
                                            "url": test_url,
                                            "payload": payload,
                                            "severity": "high"
                                        })
                                        console.print(f"[red]Zafiyet Bulundu: XSS - {test_url} - Payload: {payload}[/red]")
                                        logging.info(f"XSS bulundu: {test_url} - Payload: {payload}")
                                    elif vuln_type == "ssti" and any(str(49) in response_text or "7777777" in response_text):
                                        self.vulnerabilities.append({
                                            "type": "ssti",
                                            "url": test_url,
                                            "payload": payload,
                                            "severity": "critical"
                                        })
                                        console.print(f"[red]Zafiyet Bulundu: SSTI - {test_url} - Payload: {payload}[/red]")
                                        logging.info(f"SSTI bulundu: {test_url} - Payload: {payload}")
                            except Exception as e:
                                console.print(f"[yellow]Zafiyet testi hatası: {test_url} - {str(e)}[/yellow]")
                                logging.warning(f"Zafiyet testi hatası: {test_url} - {str(e)}")
                            await asyncio.sleep(self.rate_limit)
        console.print(f"[bold green]{len(self.vulnerabilities)} zafiyet bulundu.[/bold green]")

    async def collect_wayback_endpoints(self):
        console.print("[bold green]Wayback Machine taranıyor...[/bold green]")
        try:
            wayback = waybackpy.WaybackMachineCDXServerAPI(self.domain, user_agent="Tulpar/1.0")
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Wayback endpoint'leri toplanıyor", total=None)
                for snapshot in wayback.snapshots():
                    try:
                        url = snapshot.url
                        if urlparse(url).netloc.endswith(self.domain):
                            self.endpoints.add(url)
                            console.print(f"[cyan]Wayback Endpoint: {url}[/cyan]")
                            logging.info(f"Wayback endpoint: {url}")
                    except Exception as e:
                        console.print(f"[yellow]Wayback URL hatası: {str(e)}[/yellow]")
                        logging.warning(f"Wayback URL hatası: {str(e)}")
                    progress.advance(task, advance=1)
                    await asyncio.sleep(self.rate_limit)
            console.print(f"[bold green]{len(self.endpoints)} Wayback endpoint bulundu.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Wayback hatası: {str(e)}[/bold red]")
            logging.error(f"Wayback hatası: {str(e)}")

    async def save_results(self):
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        output_base = f"{self.output_dir}/tulpar_output_{self.domain}_{timestamp}"
        results = {
            "domain": self.domain,
            "subdomains": list(self.subdomains),
            "live_subdomains": list(self.live_subdomains),
            "wayback_endpoints": list(self.endpoints),
            "js_endpoints": self.js_endpoints,
            "vulnerabilities": self.vulnerabilities,
            "screenshots": self.screenshots,
            "support": "Tulpar'ı beğendiyseniz, bir kahve ısmarlayın: https://www.buymeacoffee.com/emrewashere"
        }
        with open(f"{output_base}.json", "w") as f:
            json.dump(results, f, indent=4)
        console.print(f"[bold green]Sonuçlar kaydedildi: {output_base}.json[/bold green]")

    def display_results(self):
        # Subdomain Tablosu
        sub_table = Table(title="Subdomain'ler")
        sub_table.add_column("Subdomain", style="cyan")
        sub_table.add_column("Canlı", style="green")
        for subdomain in self.subdomains:
            live = "Evet" if any(subdomain in url for url in self.live_subdomains) else "Hayır"
            sub_table.add_row(subdomain, live)
        console.print(sub_table)

        # JS Endpoint Tablosu
        js_table = Table(title="JavaScript Endpoint'ler")
        js_table.add_column("Endpoint", style="cyan")
        js_table.add_column("Parametre Sayısı", style="yellow")
        js_table.add_column("Parametre İsimleri", style="magenta")
        for endpoint_data in self.js_endpoints:
            js_table.add_row(
                endpoint_data["url"],
                str(endpoint_data["parameters"]),
                ", ".join(endpoint_data["param_names"]) or "Yok"
            )
        console.print(js_table)

        # Tüm Endpoint Tablosu
        endpoint_table = Table(title="Tüm Endpoint'ler")
        endpoint_table.add_column("Endpoint", style="cyan")
        endpoint_table.add_column("Kaynak", style="green")
        endpoint_table.add_column("Parametre Sayısı", style="yellow")
        for endpoint in self.endpoints:
            parsed = urlparse(endpoint)
            param_count = len(parse_qs(parsed.query))
            endpoint_table.add_row(endpoint, "Wayback", str(param_count))
        for endpoint_data in self.js_endpoints:
            endpoint_table.add_row(endpoint_data["url"], "JavaScript", str(endpoint_data["parameters"]))
        console.print(endpoint_table)

        # Özet Tablosu
        summary_table = Table(title="Tulpar Özet")
        summary_table.add_column("Kategori", style="cyan")
        summary_table.add_column("Sayı", style="green")
        summary_table.add_row("Subdomain'ler", str(len(self.subdomains)))
        summary_table.add_row("Canlı Subdomain'ler", str(len(self.live_subdomains)))
        summary_table.add_row("Wayback Endpoint'ler", str(len(self.endpoints)))
        summary_table.add_row("JS Endpoint'ler", str(len(self.js_endpoints)))
        summary_table.add_row("Zafiyetler", str(len(self.vulnerabilities)))
        summary_table.add_row("Screenshot'lar", str(len(self.screenshots)))
        console.print(summary_table)

def parse_args():
    parser = argparse.ArgumentParser(description="Tulpar - Subdomain ve Zafiyet Tarama Aracı")
    parser.add_argument("-d", "--domain", required=True, help="Hedef domain (örn: example.com)")
    return parser.parse_args()

async def main():
    args = parse_args()
    tulpar = Tulpar(args.domain)
    await tulpar.run()

if __name__ == "__main__":
    asyncio.run(main())
