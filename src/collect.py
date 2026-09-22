import os
import time
import subprocess
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

# --- Configuration ---
DOMAINS_FILE = r"src\domains.txt"
PCAPS_DIR = r"data\pcaps"
SAMPLES_PER_DOMAIN = 10       # Good baseline for 10-fold Cross Validation
DOH_RESOLVER_IP = "1.1.1.1"
DOH_RESOLVER_URL = "https://cloudflare-dns.com/dns-query"

NETWORK_INTERFACE = "4"
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
CAPTURE_DURATION = 10          # seconds; tshark self-terminates cleanly at this mark
PAGE_LOAD_TIMEOUT = 8
POST_LOAD_WAIT = 1.5
# ---------------------


def get_firefox_options():
    options = Options()
    options.add_argument("--headless")

    # Force DoH through Cloudflare
    options.set_preference("network.trr.mode", 3)
    options.set_preference("network.trr.uri", DOH_RESOLVER_URL)
    options.set_preference("network.trr.bootstrapAddress", DOH_RESOLVER_IP)

    # Disable cache so every visit is a cold, comparable trace
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("browser.cache.offline.enable", False)
    options.set_preference("network.http.use-cache", False)

    # Kill Firefox's own housekeeping traffic (also resolved via your forced
    # DoH resolver, so it would otherwise pollute every trace with noise
    # unrelated to the target site)
    options.set_preference("browser.safebrowsing.malware.enabled", False)
    options.set_preference("browser.safebrowsing.phishing.enabled", False)
    options.set_preference("datareporting.healthreport.uploadEnabled", False)
    options.set_preference("toolkit.telemetry.enabled", False)
    options.set_preference("network.captive-portal-service.enabled", False)
    options.set_preference("network.dns.disablePrefetch", True)
    options.set_preference("network.prefetch-next", False)
    options.set_preference("app.update.enabled", False)

    return options


def capture_sample(domain, sample_index):
    pcap_filename = os.path.join(PCAPS_DIR, f"{domain}_{sample_index}.pcap")
    print(f"[*] Capturing: {domain} (Sample {sample_index}/{SAMPLES_PER_DOMAIN})")

    tshark_cmd = [
        TSHARK_PATH,
        "-i", NETWORK_INTERFACE,
        "-w", pcap_filename,
        "-f", f"host {DOH_RESOLVER_IP} and port 443",
        "-a", f"duration:{CAPTURE_DURATION}",   # tshark exits on its own -> clean file close
    ]

    tshark_process = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(1)  # let tshark attach before the browser starts

    driver = None
    try:
        driver = webdriver.Firefox(options=get_firefox_options())
        driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
        driver.get(f"https://{domain}")
        time.sleep(POST_LOAD_WAIT)

    except TimeoutException:
        print(f"[!] Timeout loading {domain} ({PAGE_LOAD_TIMEOUT}s hit). Capturing what we have...")
    except WebDriverException as e:
        print(f"[!] WebDriver error for {domain}: {e}")
    except Exception as e:
        print(f"[!] Unexpected error for {domain}: {e}")

    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass

        # tshark is on a duration timer, so just wait for it to exit on its
        # own rather than killing it mid-write
        try:
            tshark_process.wait(timeout=CAPTURE_DURATION + 5)
        except subprocess.TimeoutExpired:
            tshark_process.terminate()
            tshark_process.wait()


def main():
    if not os.path.exists(PCAPS_DIR):
        os.makedirs(PCAPS_DIR)

    with open(DOMAINS_FILE, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        for i in range(1, SAMPLES_PER_DOMAIN + 1):
            capture_sample(domain, i)

    print("[+] Data collection complete.")


if __name__ == "__main__":
    main()