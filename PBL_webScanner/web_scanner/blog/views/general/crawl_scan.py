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

def crawl_and_scan(base_url, options, depth=0, max_depth=3):
    if depth > max_depth or base_url in visited_urls:
        return [], [], []   # 최대 깊이를 초과하면 탐색을 중단&이미 검사한 url이면 검사 건너뜀
    
    visited_urls.add(base_url)

    try:
        # 옵션 생성
        op = webdriver.ChromeOptions()
        # 창 숨기는 옵션 추가
        op.add_argument("headless")
        # Selenium 웹 드라이버 초기화
        driver = webdriver.Chrome(options=op)  # 또는 다른 드라이버 선택

        # 기본 URL에 접속
        driver.get(base_url)

        # 현재 페이지의 HTML을 가져오기
        html_content = driver.page_source

        soup = BeautifulSoup(html_content, "html.parser")


        # links = []
        # links.append(base_url)
        links = set()
        links.add(base_url)

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")
            result = urljoin(base_url, href)

            if result and result.startswith(base_url):
                # links.append(result)
                links.add(result)

        # onclick 속성 찾아 window.open()을 호출할 때의 url 추출
        for element in soup.find_all(lambda tag: tag.has_attr('onclick')):
            onclick_value = element['onclick']
            if 'window.open(' in onclick_value:
                # onclick에 "window.open("가 포함되어 있다면, 자바 스크립트 내 싱글 쿼트로 감싸인 URL 부분을 추출. 
                window_open_url = onclick_value.split("'")[1] # 인덱스 1에 해당하는 값
                links.add(urljoin(base_url, window_open_url))
                # links.append(urljoin(base_url, window_open_url))
        

        # 출력을 위해 links 변수에 들어간 URL들을 확인
        print("Final URLs in the links variable:")
        for url in links:
            print(url)
    

        all_xss_vulnerabilities = []
        all_sql_vulnerabilities = []
        all_csrf_vulnerabilities = []


        threads = []
        
        for url in links:
            print(f"Checking URL: {url}")

            if "전체" in options or "XSS" in options or "CSRF" in options:
                thread = threading.Thread(target=xss_detection, args=(url, all_xss_vulnerabilities))
                thread.start()
                thread.join()  # XSS 검사가 끝날 때까지 기다림

                xss_detected = bool(all_xss_vulnerabilities)
                if "XSS" in options:
                    print(f"XSS Detected in {url}: {xss_detected}")

                if xss_detected and ("전체" in options or "CSRF" in options):
                    thread = threading.Thread(target=csrf_detection, args=(url, all_csrf_vulnerabilities))
                    thread.start()
                    thread.join()  # CSRF 검사가 끝날 때까지 기다림

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
            
        # 모든 쓰레드가 완료될 때까지 기다림
        for thread in threads:
            thread.join()

    except Exception as e:
        print(f"Error while crawling and scanning: {e}")
        return [], 0, [], 0, [], 0
    
    finally:

        # 재귀 호출로 하위 링크 탐색
        for url in links:
            sub_xss_vulns, sub_sql_vulns, sub_csrf_vulns = crawl_and_scan(url, options, depth+1, max_depth)
            all_xss_vulnerabilities.extend(sub_xss_vulns)
            all_sql_vulnerabilities.extend(sub_sql_vulns)
            all_csrf_vulnerabilities.extend(sub_csrf_vulns)

        # Selenium 웹 드라이버 종료
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

    if "전체" in options or "Directory Indexing" in options:
        all_directory_vulnerabilities = no_crawl(base_url, options)
        all_vulnerabilities.extend(all_directory_vulnerabilities)

    if "전체" in options or "XSS" in options or "CSRF" in options or "SQL Injection" in options:
        all_xss_vulnerabilities, all_sql_vulnerabilities, all_csrf_vulnerabilities = crawl_and_scan(base_url, options)
        all_vulnerabilities.extend(all_xss_vulnerabilities)
        all_vulnerabilities.extend(all_sql_vulnerabilities)
        all_vulnerabilities.extend(all_csrf_vulnerabilities)

    return all_vulnerabilities