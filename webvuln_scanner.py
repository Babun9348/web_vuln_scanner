import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import threading                                                                             
import time
import nmap
import os
from datetime import datetime

class WebVulnScanner:
    def __init__(self, base_url, delay=1):
        self.base_url = base_url
        self.session = requests.Session()
        self.nm = nmap.PortScanner()
        self.delay = delay
        self.vulnerabilities = {
            'xss': [],
            'sql': [],
            'forms': [],
            'headers': []
        }                                                                                                                            
        self.visited_urls = set()
        self.internal_urls = set()
        self.external_urls = set()

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def is_same_domain(self, url): 
        base_domain = urlparse(self.base_url).netloc
        return urlparse(url).netloc == base_domain

    def detect_xss(self, url, payload_file_path):
        xss_payloads = []
        try:
            with open(payload_file_path, 'r') as file:
                xss_payloads = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f'Error: Payload file {payload_file_path} not found.')
            return
        except IOError as e:
            print(f'Error reading payload file {payload_file_path}: {e}')
            return

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params_to_test = query_params.keys() if query_params else ['q', 'search', 'input']
        
        for payload in xss_payloads:
            for param in params_to_test:
                test_url = f"{url}&{param}={payload}"
                try:
                    response = self.session.get(test_url)
                    if payload in response.text:
                        print(f'[XSS] Vulnerable URL: {test_url} with payload: {payload}')
                        self.vulnerabilities['xss'].append((test_url, payload))
                except requests.RequestException as e:
                    print(f'Error detecting XSS in {test_url}: {e}')


    def detect_sql_injection(self, url, payload_file):
        if not os.path.isfile(payload_file):
            print(f'Payload file {payload_file} does not exist.')
            return

        if not self.is_valid_url(url):
            print(f'Invalid URL: {url}')
            return

        try:
            with open(payload_file, 'r') as file:
                for payload in file:
                    payload = payload.strip()
                    try:
                        response = self.session.get(url, params={'id': payload})
                        if 'syntax error' in response.text.lower() or 'sql' in response.text.lower():
                            print(f'[SQL Injection] Vulnerable URL: {url} with payload: {payload}')
                            self.vulnerabilities['sql'].append((url, payload))
                        # Blind SQL injection detection (time-based)
                        time_based_payload = f"{payload} AND SLEEP(5)"
                        start_time = time.time()
                        response = self.session.get(url, params={'id': time_based_payload})
                        if time.time() - start_time > 5:
                            print(f'[Blind SQL Injection] Vulnerable URL: {url} with payload: {time_based_payload}')
                            self.vulnerabilities['sql'].append((url, time_based_payload))
                        time.sleep(self.delay)
                    except requests.RequestException as e:
                        print(f'Error detecting SQL Injection with payload {payload}: {e}')
        except Exception as e:
            print(f'Error reading payload file {payload_file}: {e}')

    def scan_forms(self, url):
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                if action and not action.startswith(('http', 'https')):
                    action = urljoin(url, action)
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                form_details = {
                    'url': url,
                    'action': action,
                    'method': method,
                    'inputs': [{input_tag.get('name'): input_tag.get('type')} for input_tag in inputs]
                }
                print(f'Found form: {form_details}')
                self.vulnerabilities['forms'].append(form_details)
        except Exception as e:
            print(f'Error scanning forms in {url}: {e}')

    def scan_headers(self, url):
        try:
            response = self.session.get(url)
            response.raise_for_status()
            security_headers = ['Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security']
            missing_headers = [header for header in security_headers if header not in response.headers]
            if missing_headers:
                print(f'[Header Missing] {missing_headers} not found in {url}')
                self.vulnerabilities['headers'].append((url, missing_headers))
        except Exception as e:
            print(f'Error scanning headers in {url}: {e}')

    def nmap_scan(self, target, nmap_args):
        try:
            print(f'Starting Nmap scan on {target} with arguments: {nmap_args}...')
            self.nm.scan(target, arguments=nmap_args)
            nmap_results = []
            for host in self.nm.all_hosts():
                result = {
                    'host': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': []
                }
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    proto_result = {
                        'protocol': proto,
                        'ports': []
                    }
                    for port in ports:
                        proto_result['ports'].append({
                            'port': port,
                            'state': self.nm[host][proto][port]['state'],
                            'service': self.nm[host][proto][port]['name']
                        })
                    result['protocols'].append(proto_result)
                nmap_results.append(result)
            
            with open('nmap_report.txt', 'w') as report:
                report.write('Nmap Scan Report\n')
                report.write('=' * 20 + '\n\n')
                for result in nmap_results:
                    report.write(f"Host: {result['host']} ({result['hostname']})\n")
                    report.write(f"State: {result['state']}\n")
                    for proto in result['protocols']:
                        report.write(f"Protocol: {proto['protocol']}\n")
                        for port in proto['ports']:
                            report.write(f"  Port: {port}\tState: {port['state']}\tService: {port['service']}\n")
                        report.write('\n')

            print('Nmap report generated: nmap_report.txt')
        except Exception as e:
            print(f'Error during Nmap scan: {e}')

    def crawl(self, url):
        print(f'Crawling URL: {url}')
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link['href']
                href = urljoin(url, href)
                if self.is_valid_url(href) and self.is_same_domain(href):
                    if href not in self.visited_urls:
                        self.internal_urls.add(href)
                        print(f'Found internal link: {href}')
                        self.crawl(href)
                else:
                    print(f'Found external link: {href}')
                    self.external_urls.add(href)
        
        except requests.RequestException as e:
            print(f'Error crawling {url}: {e}')

    def generate_xss_report(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open('xss_report.txt', 'w') as report:
                report.write('XSS Vulnerability Scan Report\n')
                report.write('=' * 30 + '\n')
                report.write(f'Scan Date: {timestamp}\n\n')

                # XSS
                if self.vulnerabilities['xss']:
                    for url, payload in self.vulnerabilities['xss']:
                        report.write(f'URL: {url}\nPayload: {payload}\n\n')
                else:
                    report.write('No XSS vulnerabilities found.\n\n')
            print('XSS report generated: xss_report.txt')
        except IOError as e:
            print(f'Error generating XSS report: {e}')

    def generate_sql_report(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open('sql_report.txt', 'w') as report:
                report.write('SQL Injection Vulnerability Scan Report\n')
                report.write('=' * 30 + '\n')
                report.write(f'Scan Date: {timestamp}\n\n')

                # SQL Injection
                if self.vulnerabilities['sql']:
                    for url, payload in self.vulnerabilities['sql']:
                        report.write(f'URL: {url}\nPayload: {payload}\n\n')
                else:
                    report.write('No SQL Injection vulnerabilities found.\n\n')
            print('SQL Injection report generated: sql_report.txt')
        except IOError as e:
            print(f'Error generating SQL Injection report: {e}')

    def generate_form_report(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open('form_report.txt', 'w') as report:
                report.write('Form Scanning Report\n')
                report.write('=' * 30 + '\n')
                report.write(f'Scan Date: {timestamp}\n\n')

                # Forms
                if self.vulnerabilities['forms']:
                    for form in self.vulnerabilities['forms']:
                        report.write(f"URL: {form['url']}\nAction: {form['action']}\nMethod: {form['method']}\n")
                        for input_tag in form['inputs']:
                            report.write(f'Input: {input_tag}\n')
                        report.write('\n')
                else:
                    report.write('No forms found.\n\n')
            print('Form report generated: form_report.txt')
        except IOError as e:
            print(f'Error generating Form report: {e}')

    def generate_header_report(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open('header_report.txt', 'w') as report:
                report.write('Security Headers Scan Report\n')
                report.write('=' * 30 + '\n')
                report.write(f'Scan Date: {timestamp}\n\n')

                # Headers
                if self.vulnerabilities['headers']:
                    for url, headers in self.vulnerabilities['headers']:
                        report.write(f'URL: {url}\nMissing Headers: {", ".join(headers)}\n\n')
                else:
                    report.write('No missing security headers found.\n\n')
            print('Security headers report generated: header_report.txt')
        except IOError as e:
            print(f'Error generating Header report: {e}')
    def get_scan_options(self):
        print("Select the types of scans you want to perform (comma-separated):")
        print("1. XSS")
        print("2. SQL Injection")
        print("3. Form Scanning")
        print("4. Security Headers Scanning")
        print("5. Nmap Scan")
        print("6. EXIT")
        
        scan_types = input("Enter your choices (e.g., 1,2,3,4,5,6): ")
        scan_types = scan_types.split(',')

        self.scan_options = {}
        if '1' in scan_types:
            self.scan_options['xss'] = input("Enter the XSS payload file path: ")
        if '2' in scan_types:
            self.scan_options['sql'] = input("Enter the SQL Injection payload file path: ")
        if '3' in scan_types:
            self.scan_options['forms'] = True  # Indicates that form scanning is selected
        if '4' in scan_types:
            self.scan_options['headers'] = True  # Indicates that headers scanning is selected
        if '5' in scan_types:
            self.scan_options['nmap'] = True  # Indicates that Nmap scan is selected
        if '6' in scan_types:
            exit()


    def scan(self):
        print(f'Starting scan on {self.base_url}')
        self.get_scan_options()  # Get user input for scan options
        self.crawl(self.base_url)

        # Run XSS detection
        if 'xss' in self.scan_options:
            print('Running XSS detection...')
            for url in self.internal_urls:
                self.detect_xss(url, self.scan_options['xss'])
            self.generate_xss_report()

        # Run SQL Injection detection
        if 'sql' in self.scan_options:
            print('Running SQL Injection detection...')
            for url in self.internal_urls:
                self.detect_sql_injection(url, self.scan_options['sql'])
            self.generate_sql_report()

        # Run form scanning
        if 'forms' in self.scan_options:
            print('Running form scanning...')
            for url in self.internal_urls:
                self.scan_forms(url)
            self.generate_form_report()

        # Run headers scanning
        if 'headers' in self.scan_options:
            print('Running security headers scanning...')
            for url in self.internal_urls:
                self.scan_headers(url)
            self.generate_header_report()

        # Run Nmap scan
        if 'nmap' in self.scan_options:
            print('Running Nmap scan...')
            parsed_url = urlparse(self.base_url)
            base_domain = parsed_url.netloc
            nmap_args = '-sS -O -Pn'
            self.nmap_scan(base_domain, nmap_args)
            

        print('Scan complete.')
def print_banner():
        
    banner = """
    =================================================
    Welcome to the Web Vulnerability Scanner
    =================================================


'##::::'##:::'###::::'######:'##:::'##'########'########:::::'#####:::'#######::
 ##:::: ##::'## ##::'##... ##:##::'##::##.....::##.... ##:::'##.. ##:'##.... ##:
 ##:::: ##:'##:. ##::##:::..::##:'##:::##:::::::##:::: ##::'##:::: ##:##:::: ##:
 #########'##:::. ##:##:::::::#####::::######:::########::::##:::: ##: #######::
 ##.... ##:#########:##:::::::##. ##:::##...::::##.. ##:::::##:::: ##'##.... ##:
 ##:::: ##:##.... ##:##::: ##:##:. ##::##:::::::##::. ##:::. ##:: ##::##:::: ##:
 ##:::: ##:##:::: ##. ######::##::. ##:########:##:::. ##:::. #####::. #######::
..:::::..:..:::::..::......::..::::..:........:..:::::..:::::.....::::.......:::


    This tool performs various security scans on web applications, including:
    - XSS Detection
    - SQL Injection Detection
    - Form Scanning
    - Security Headers Analysis
    - Nmap Scanning
    """

    print(banner)
# Main function to run the scanner
if __name__ == '__main__':
    print_banner()  # Print the banner at the start
    target_url = input("Enter the target URL: ")
    scanner = WebVulnScanner(target_url)
    scanner.scan()  