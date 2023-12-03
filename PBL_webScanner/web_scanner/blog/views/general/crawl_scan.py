from bs4 import BeautifulSoup
import threading
from selenium import webdriver
from ..detection.csrf_detection import csrf_detection
from ..detection.directory_indexing_detection import directory_indexing_detection
from ..detection.sql_injection_detection import sql_injection_detection
from ..detection.xss_detection import xss_detection
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlsplit, urlunsplit

#이미 검사한 url을 저장 
visited_urls = set()

all_directory_vulnerabilities = []
all_xss_vulnerabilities = []
all_sql_vulnerabilities = []
all_csrf_vulnerabilities = []

def crawl_and_scan(base_url, options, depth=0, max_depth=3):
    all_xss_vulnerabilities = []
    all_sql_vulnerabilities = []
    all_csrf_vulnerabilities = []

    if depth > max_depth or base_url in visited_urls:
        return all_xss_vulnerabilities, all_sql_vulnerabilities, all_csrf_vulnerabilities

    visited_urls.add(base_url)

    try:
        op = webdriver.ChromeOptions()
        op.add_argument('headless')
        driver = webdriver.Chrome(options=op)

        driver.get(base_url)
        html_content = driver.page_source
        soup = BeautifulSoup(html_content, "html.parser")

        links_to_visit = set()

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")
            result = urljoin(base_url, href)
            if result and result.startswith(base_url) and result not in visited_urls:
                links_to_visit.add(result)

        for element in soup.find_all(lambda tag: tag.has_attr('onclick')):
            onclick_value = element['onclick']
            if 'window.open(' in onclick_value:
                window_open_url = onclick_value.split("'")[1]
                if window_open_url not in visited_urls:
                    links_to_visit.add(urljoin(base_url, window_open_url))

        for url in links_to_visit:
            sub_xss_vulns, sub_sql_vulns, sub_csrf_vulns = crawl_and_scan(url, options, depth+1, max_depth)
            all_xss_vulnerabilities.extend(sub_xss_vulns)
            all_sql_vulnerabilities.extend(sub_sql_vulns)
            all_csrf_vulnerabilities.extend(sub_csrf_vulns)

        threads = []

        for url in visited_urls:
            print(f"Checking URL: {url}")

            if "전체" in options or "XSS" in options or "CSRF" in options:
                thread = threading.Thread(target=xss_detection, args=(url, all_xss_vulnerabilities))
                thread.start()
                threads.append(thread)

                xss_detected = bool(all_xss_vulnerabilities)
                if "XSS" in options:
                    print(f"XSS Detected in {url}: {xss_detected}")

                if xss_detected and ("전체" in options or "CSRF" in options):
                    thread = threading.Thread(target=csrf_detection, args=(url, all_csrf_vulnerabilities))
                    thread.start()
                    threads.append(thread)

                    csrf_detected = bool(all_csrf_vulnerabilities)
                    print(f"CSRF Detected in {url}: {csrf_detected}")
                elif "CSRF" in options:
                    print("XSS 취약점이 탐지되지 않아 CSRF 공격 불가능")

            if "전체" in options or "SQL Injection" in options:
                thread = threading.Thread(target=sql_injection_detection, args=(url, all_sql_vulnerabilities))
                threads.append(thread)
                thread.start()

                sql_injection_detected = bool(all_sql_vulnerabilities)
                print(f"SQL Injection Detected in {url}: {sql_injection_detected}")

        for thread in threads:
            thread.join()

    except Exception as e:
        print(f"Error while crawling and scanning: {e}")
        return [], [], []

    finally:
        driver.quit()

    return all_xss_vulnerabilities, all_sql_vulnerabilities, all_csrf_vulnerabilities

    
def no_crawl(base_url, options):
    all_directory_vulnerabilities = []

    threads = []

    if "전체" in options or "Directory Indexing" in options:
        thread = threading.Thread(target=directory_indexing_detection, args=(base_url, all_directory_vulnerabilities))
        threads.append(thread)
        thread.start()

    # 모든 쓰레드가 완료될 때까지 기다림
    for thread in threads:
        thread.join()

    return all_directory_vulnerabilities

def scan(base_url, options):
    all_vulnerabilities = []

    # 각각의 함수를 별도의 스레드에서 실행
    no_crawl_thread = threading.Thread(target=no_crawl, args=(base_url, options))
    crawl_and_scan_thread = threading.Thread(target=crawl_and_scan, args=(base_url, options))

    # 스레드 시작
    no_crawl_thread.start()
    crawl_and_scan_thread.start()

    # 모든 스레드가 완료될 때까지 기다림
    no_crawl_thread.join()
    crawl_and_scan_thread.join()

    # 스레드에서 수집한 결과를 모두 합침
    all_vulnerabilities.extend(all_directory_vulnerabilities)
    all_vulnerabilities.extend(all_xss_vulnerabilities)
    all_vulnerabilities.extend(all_sql_vulnerabilities)
    all_vulnerabilities.extend(all_csrf_vulnerabilities)

    return all_vulnerabilities