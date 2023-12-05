import requests
from bs4 import BeautifulSoup
import logging
from requests.exceptions import RequestException
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlsplit, urlunsplit
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from time \
import sleep
from selenium import webdriver


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def xss_detection(url, vulnerabilities, detectBool):
    logger.info("Starting XSS detection...")

    fname = "blog/payloads/xss.txt"
    # 예외 처리(페이로드 파일 못 받을 시 바로 함수 종료(이유, xss 판단 불가))
    try:
        with open(fname) as f:
            content = f.readlines()
    except FileNotFoundError:
        print(f"Error: 파일 '{fname}'을 찾을 수 없습니다.")
        return
    payloads = [x.strip() for x in content]

    try:
        # 세션 시작
        session = requests.Session()

        # 웹 페이지 불러오기
        response = session.get(url)
        response.raise_for_status()  # HTTP 에러 발생 시 예외 발생
        soup = BeautifulSoup(response.text, "html.parser")

        # 폼 요소 찾기
        forms = soup.find_all("form")
        if not forms:
            print("폼이 없습니다.")
            detectBool.clear()
            return

        if forms:
            for form in forms:
                # 폼 액션 URL과 전송 방식 가져오기
                form_action = form.get("action")
                if form_action is None:
                    form_action = url
                else:
                    form_action = urljoin(url, form_action)
                    
                form_method = form.get("method")

                if form_method is None:
                    form_method = "get"
                else:
                    form_method = form_method.lower()

                # GET 방식으로 폼 요청 처리
                if form_method == "get":
                    print("GET METHOD")
                    for input_field in form.find_all("input"):
                        input_name = input_field.get("name")
                        input_type = input_field.get("type")

                        # "submit" 타입의 입력 필드에 대해 페이로드 주입하지 않음(버튼이기 때문)
                        if input_type != "submit":
                            for payload in payloads:
                                encoded_payload = {input_name: payload}
                                query_string = urlencode(encoded_payload)
                                payload_url = urljoin(url, form_action) + "?" + query_string
                                print("주입된 url : %s", payload_url)

                                # 옵션 생성
                                op = webdriver.ChromeOptions()
                                # 창 숨기는 옵션 추가
                                op.add_argument("headless")

                                # Selenium을 사용하여 Alert 창 감지
                                driver = webdriver.Chrome(options=op)

                                try:
                                    driver.get(payload_url)
                                    alert = WebDriverWait(driver, 5).until(EC.alert_is_present())
                                    # Alert이 나타나면 accept()를 호출하여 OK 버튼을 클릭
                                    alert.accept()
                                    split_url = urlsplit(url)
                                    no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                                    vulnerabilities.append(no_query_url)
                                    detectBool.append(url)
                                    print(f"XSS 취약점이 발견된 URL (GET 방식): {url} 주입된 페이로드: {payload}")
                                    driver.quit()
                                    return
                                except:
                                    print('Alert이 나타나지 않음')
                                    continue

                # POST 방식으로 폼 요청 처리
                elif form_method == "post":
                    print("form_method : POST")
                    form_action = urljoin(url, form_action)
                    form_data = {}

                    submit_input_names = [input_field.get("name") for input_field in form.find_all("input") if input_field.get("type") == "submit"]
                    
                    for input_field in form.find_all("input"):
                        input_name = input_field.get("name")
                        input_type = input_field.get("type")

                        # "submit" 타입의 입력 필드에 대해 페이로드 주입하지 않음
                        if input_type != "submit":
                            for payload in payloads:
                                form_data[input_name] = payload
                                print("POST's data : ", form_data)

                                # 옵션 생성
                                op = webdriver.ChromeOptions()
                                # 창 숨기는 옵션 추가
                                op.add_argument("headless")

                                # Selenium을 사용하여 Alert 창 감지
                                driver = webdriver.Chrome(options=op)
                                try:
                                    driver.get(url)
                                    driver.find_element(By.NAME, input_name).send_keys(payload)
                                    sleep(5)

                                    for button in submit_input_names:
                                        driver.find_element(By.NAME, button).click()

                                    # WebDriverWait를 사용하여 Alert이 나타날 때까지 기다림
                                    alert = WebDriverWait(driver, 3).until(EC.alert_is_present())

                                    # Alert이 나타나면 accept()를 호출하여 OK 버튼을 클릭
                                    alert.accept()
                                    split_url = urlsplit(url)
                                    no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                                    vulnerabilities.append(no_query_url)
                                    detectBool.append(url)
                                    print(f"XSS 취약점이 발견된 URL (POST 방식): {url} 주입된 페이로드: {payload}")
                                    driver.quit()
                                    return
                                except:
                                    print('XSS 취약점이 존재하지 않습니다.')
                                    continue      
                    # textarea가 있는 경우에만 동작
                    textarea = form.find("textarea")
                    if textarea:
                        input_name = textarea.get("name")

                        for payload in payloads:
                            form_data[input_name] = payload
                            print("POST's data : ", form_data)

                            # 옵션 생성
                            op = webdriver.ChromeOptions()
                            # 창 숨기는 옵션 추가
                            op.add_argument("headless")

                            # Selenium을 사용하여 Alert 창 감지
                            driver = webdriver.Chrome(options=op)

                            try:
                                driver.get(url)
                                driver.find_element(By.NAME, input_name).send_keys(payload)

                                for button in submit_input_names:
                                    driver.find_element(By.NAME, button).click()

                                # WebDriverWait를 사용하여 Alert이 나타날 때까지 기다림
                                alert = WebDriverWait(driver, 5).until(EC.alert_is_present())

                                # Alert이 나타나면 accept()를 호출하여 OK 버튼을 클릭
                                alert.accept()
                                split_url = urlsplit(url)
                                no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                                vulnerabilities.append(no_query_url)
                                detectBool.append(url)
                                print(f"XSS 취약점이 발견된 URL (POST 방식): {url} 주입된 페이로드: {payload}")
                                driver.quit()
                                return
                            except:
                                print('XSS 취약점이 존재하지 않습니다.')
                                continue
        driver.quit()

        logger.info("Finished XSS detection.")

    except RequestException as e:
        detectBool.clear()
        print(f"Error during HTTP request: {e}")