from bs4 import BeautifulSoup
import threading
from selenium import webdriver
from ..detection.csrf_detection import csrf_detection
from ..detection.directory_indexing_detection import directory_indexing_detection
from ..detection.sql_injection_detection import sql_injection_detection
from ..detection.xss_detection import xss_detection
from urllib.parse import urljoin, urlsplit

#이미 검사한 url을 저장 
visited_urls = set()

all_directory_vulnerabilities = []
all_xss_vulnerabilities = []
all_sql_vulnerabilities = []
all_csrf_vulnerabilities = []
max_depth=3

def crawl(url):
    try:
        print(f'crawl 시작: {url}')
        op = webdriver.ChromeOptions()
        op.add_argument('headless')
        driver = webdriver.Chrome(options=op)

        driver.get(url)
        html_content = driver.page_source
        soup = BeautifulSoup(html_content, "html.parser")

        links_to_visit = []

        # 웹사이트의 기본 URL을 가져옵니다.
        base_url = "{0.scheme}://{0.netloc}".format(urlsplit(url))

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")
            result = urljoin(base_url, href)
            if result and result.startswith(base_url):
                links_to_visit.append(result)

        # div 태그 중 class가 story인 태그 안의 a 태그를 찾는 코드 추가
        for div in soup.find_all("div", class_="story"):
            for anchor in div.find_all("a", href=True):
                href = anchor.get("href")
                result = urljoin(base_url, href)
                if result and result.startswith(base_url):
                    links_to_visit.append(result)

        for element in soup.find_all(lambda tag: tag.has_attr('onclick')):
            onclick_value = element['onclick']
            if 'window.open(' in onclick_value:
                window_open_url = onclick_value.split("'")[1]
                links_to_visit.append(urljoin(base_url, window_open_url))
        
        visited_urls.update(links_to_visit)

        for url in visited_urls:  
            print(f"Checking URL: {url}")

    except Exception as e:
        print(f"Error while crawling and scanning: {e}")
        return [], [], []

    finally:
        driver.quit()

    return


def crawl_and_scan(base_url, options):
    all_xss_vulnerabilities = []
    all_sql_vulnerabilities = []
    all_csrf_vulnerabilities = []
    detectBool = []
    crawl_urls = set()
    local_visited_urls = set()

    for _ in range(max_depth):
        if crawl_urls:
            for urls in crawl_urls:
                if urls not in local_visited_urls:
                    print(f'{urls}: crawl{_}')
                    crawl(urls)
                    local_visited_urls.add(urls)
            crawl_urls.update(visited_urls)
        else:
            print(f'{base_url}: crawl{_}')
            crawl(base_url)
            local_visited_urls.update(base_url)
            crawl_urls.update(visited_urls)



    threads = []



    for url in visited_urls:

        if "전체" in options or "XSS" in options or "CSRF" in options:
            thread = threading.Thread(target=xss_detection, args=(url, all_xss_vulnerabilities, detectBool))
            thread.start()
            threads.append(thread)

            thread.join()

            xss_detected = bool(detectBool)
            if "XSS" in options:
                print(f"XSS Detected in {url}: {xss_detected}")

            if xss_detected and ("전체" in options or "CSRF" in options):
                thread = threading.Thread(target=csrf_detection, args=(url, all_csrf_vulnerabilities))
                thread.start()
                threads.append(thread)

                thread.join()

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
