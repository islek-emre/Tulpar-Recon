# Tulpar-Recon
Tulpar - A powerful subdomain enumeration and vulnerability scanning tool for bug bounty hunters. Features include Subfinder integration, JavaScript endpoint extraction, Wayback Machine crawling, and automated testing for open redirect, path traversal, XSS, and SSTI vulnerabilities. Outputs detailed tables and JSON reports.

English:

Tulpar is a bug bounty tool that enumerates subdomains using Subfinder, extracts endpoints from JavaScript files and Wayback Machine, and scans for vulnerabilities like open redirect, path traversal, XSS, and SSTI. It provides detailed tables and JSON reports.

Türkçe:

Tulpar, bug bounty için subdomain’leri Subfinder ile bulan, JavaScript dosyalarından ve Wayback Machine’den endpoint’ler çeken, açık yönlendirme, yol geçişi, XSS ve SSTI gibi zafiyetleri tarayan bir araçtır. Ayrıntılı tablolar ve JSON raporlar sunar.

# Install Python dependencies
pip install aiohttp waybackpy rich requests pillow
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# Check Subfinder config (optional)
mkdir -p /root/.config/subfinder
echo "" > /root/.config/subfinder/provider-config.yaml
