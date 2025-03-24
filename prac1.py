import requests
import urllib.parse
import socket
import ssl
from bs4 import BeautifulSoup  # Optional, for more advanced content analysis later

def check_security_headers(url):
    """Checks for common security headers."""
    try:
        response = requests.get(url, verify=True, timeout=10)  # verify=True for SSL cert validation
        headers = response.headers
        print("\n--- Security Header Checks ---")

        security_headers = {
            "X-Frame-Options": "Clickjacking Protection",
            "Content-Security-Policy": "Cross-Site Scripting (XSS) Prevention",
            "X-Content-Type-Options": "MIME-Sniffing Protection",
            "Strict-Transport-Security": "HTTPS Enforcement (HSTS)",
            "Referrer-Policy": "Referrer Information Control",
            "Permissions-Policy": "Browser Feature Control (Modern)", # Or Feature-Policy (older)
        }

        for header, description in security_headers.items():
            if header in headers:
                print(f"[+] {header}: Present - {description}")
                header_value = headers.get(header)
                if header == "Content-Security-Policy":
                    print(f"    Value: {header_value}") # Consider further analysis of CSP value
                elif header == "Strict-Transport-Security":
                    print(f"    Value: {header_value}") # Consider checking max-age, includeSubDomains
            else:
                print(f"[-] {header}: Missing - {description} (Potential vulnerability)")

    except requests.exceptions.RequestException as e:
        print(f"Error checking headers: {e}")
    except ssl.SSLError as e:
        print(f"SSL Certificate Error: {e}")


def check_https(url):
    """Checks if the website uses HTTPS."""
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "https":
        print("\n--- HTTPS Check ---")
        print(f"[-] Website does not use HTTPS by default. Consider enforcing HTTPS redirection.")
    else:
        print("\n--- HTTPS Check ---")
        print(f"[+] Website uses HTTPS.")


def check_robots_txt_sitemap(url):
    """Checks for robots.txt and sitemap.xml."""
    print("\n--- Robots.txt and Sitemap Checks ---")
    files_to_check = ["robots.txt", "sitemap.xml"]
    for file in files_to_check:
        file_url = urllib.parse.urljoin(url, file)
        try:
            response = requests.get(file_url, verify=True, timeout=5)
            if response.status_code == 200:
                print(f"[+] {file}: Found at {file_url}")
                if file == "robots.txt":
                    # You could potentially parse robots.txt to look for disallowed paths (info gathering)
                    pass
                elif file == "sitemap.xml":
                    # You could parse sitemap.xml to understand site structure (info gathering)
                    pass
            elif response.status_code == 404:
                print(f"[-] {file}: Not found (This is not necessarily a vulnerability)")
            else:
                print(f"[!] {file}: Status code {response.status_code} - Investigate.")
        except requests.exceptions.RequestException as e:
            print(f"Error checking {file}: {e}")


def basic_cms_detection(url):
    """Basic CMS/Framework detection (very rudimentary)."""
    print("\n--- Basic CMS/Framework Detection ---")
    common_indicators = {
        "WordPress": ["wp-content", "wp-admin", "wordpress"],
        "Joomla": ["/administrator/", "joomla"],
        "Drupal": ["/sites/default/", "drupal"],
        "Magento": ["/skin/frontend/", "/js/mage/", "magento"],
        "PHP": [".php"], # Very broad, PHP is widely used
        "ASP.NET": [".aspx", ".cshtml"], # Also broad
        # Add more CMS/framework indicators as needed
    }

    try:
        response = requests.get(url, verify=True, timeout=5)
        if response.status_code == 200:
            content = response.text.lower()
            headers = response.headers

            detected_cms = []
            for cms, indicators in common_indicators.items():
                for indicator in indicators:
                    if indicator in content.lower() or indicator in str(headers).lower() : # Check headers too
                        detected_cms.append(cms)
                        break # Avoid adding same CMS multiple times if multiple indicators found

            if detected_cms:
                print(f"[+] Potential CMS/Framework detected: {', '.join(detected_cms)}")
            else:
                print("[-] CMS/Framework detection inconclusive (basic checks).")
        else:
            print(f"[!] Could not fetch website for CMS detection (Status code: {response.status_code})")

    except requests.exceptions.RequestException as e:
        print(f"Error during CMS detection: {e}")


def check_cookies_flags(url):
    """Checks for HttpOnly and Secure flags on cookies."""
    try:
        response = requests.get(url, verify=True, timeout=5)
        cookies = response.cookies
        print("\n--- Cookie Flag Checks ---")
        if cookies:
            for cookie in cookies:
                print(f"Cookie: {cookie.name}")
                if cookie.has_nonstandard_attr('httponly'): # Use has_nonstandard_attr for httponly
                    print(f"  [+] HttpOnly Flag: Present (Good)")
                else:
                    print(f"  [-] HttpOnly Flag: Missing (Consider adding)")
                if cookie.secure:
                    print(f"  [+] Secure Flag: Present (Good - for HTTPS)")
                else:
                    print(f"  [-] Secure Flag: Missing (Consider adding, especially over HTTPS)")
        else:
            print("[-] No cookies set by the website.")

    except requests.exceptions.RequestException as e:
        print(f"Error checking cookies: {e}")


def basic_port_scan(url):
    """Basic TCP port scan for common ports (limited and rudimentary)."""
    print("\n--- Basic Port Scan (Limited) ---")
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.netloc or parsed_url.path # Handle cases with just domain or full URL
    if ":" in hostname: # Remove port if present in URL
        hostname = hostname.split(":")[0]

    common_ports = [80, 443, 21, 22, 25] # HTTP, HTTPS, FTP, SSH, SMTP
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"Scanning host: {hostname} ({ip_address}) for common ports...")
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2) # Short timeout for each port
            try:
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    print(f"  [+] Port {port}: Open")
                else:
                    print(f"  [-] Port {port}: Closed/Filtered") # Could be filtered, not necessarily closed
            except Exception as e:
                print(f"  [!] Error checking port {port}: {e}")
            finally:
                sock.close()
    except socket.gaierror:
        print(f"[-] Could not resolve hostname: {hostname}")
    except Exception as e:
        print(f"Error during port scan: {e}")


def web_security_audit(url_to_audit):
    """Performs basic web security audit checks."""
    print(f"Starting basic security audit for: {url_to_audit}")

    if not url_to_audit.startswith("http://") and not url_to_audit.startswith("https://"):
        url_to_audit = "https://" + url_to_audit  # Default to HTTPS if no scheme provided

    check_https(url_to_audit)
    check_security_headers(url_to_audit)
    check_robots_txt_sitemap(url_to_audit)
    basic_cms_detection(url_to_audit)
    check_cookies_flags(url_to_audit)
    basic_port_scan(url_to_audit)

    print("\n--- Audit Finished ---")
    print("Note: This is a basic automated audit. Further manual testing and analysis are recommended.")


if __name__ == "__main__":
    target_url = input("Enter the URL to audit (e.g., https://example.com): ")
    if target_url:
        web_security_audit(target_url)
    else:
        print("Please provide a URL to audit.")