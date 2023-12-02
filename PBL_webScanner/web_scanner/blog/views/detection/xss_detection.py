import requests
from bs4 import BeautifulSoup
import logging
from requests.exceptions import RequestException
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlsplit, urlunsplit



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def xss_detection(url, vulnerabilities):
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
        soup = BeautifulSoup(response.text, "html.parser")

        # 폼 요소 찾기
        forms = soup.find_all("form")
        if not forms:
            print("폼이 없습니다.")
            return

        vulnerable_urls = []

        if forms:
            for form in forms:
                # 폼 액션 URL과 전송 방식 가져오기
                form_action = form.get("action")
                if form_action is None:
                    form_action = url
                else:
                    form_action = urljoin(url, form_action)
                    
                form_method = form.get("method").lower()

                if form_method is None:
                    form_method = "get"
                else:
                    form_method = form_method.lower()

                # print("폼 액션 : ",form_action)
                # print("폼 메소드 : ",form_method)

                # GET 방식으로 폼 요청 처리
                if form_method == "get":
                    print("GET METHOD")
                    for input_field in form.find_all("input"):
                        input_name = input_field.get("name")
                        input_type = input_field.get("type")

                        # "submit" 타입의 입력 필드에 대해 페이로드 주입하지 않음(버튼이기 때문)
                        if input_type != "submit":
                            for payload in payloads:
                                if payload is not None:  # 추가된 None 체크
                                    encoded_payload = {input_name: payload}
                                    query_string = urlencode(encoded_payload)
                                    payload_url = urljoin(url, form_action) + "?" + query_string # ex)http://testphp.vulnweb.com/search.php?searchFor=hello%21
                                    print("주입된 url : %s", payload_url)
                                    get_response = session.get(payload_url)

                                    if get_response.text is not None and payload.lower() in get_response.text.lower():  # 추가된 None 체크
                                        vulnerable_urls.append(url)
                                        print(f"XSS 취약점이 발견된 URL (GET 방식): {url} 페이로드: {payload}")

                # POST 방식으로 폼 요청 처리
                elif form_method == "post":
                    print("form_method : POST")
                    form_action = urljoin(url, form_action)
                    form_data = {}
                    for input_field in form.find_all("input"):
                        input_name = input_field.get("name")
                        input_type = input_field.get("type")

                        # "submit" 타입의 입력 필드에 대해 페이로드 주입하지 않음
                        if input_type != "submit":
                            for payload in payloads:
                                if payload is not None:
                                    form_data[input_name] = payload
                                    response = session.post(form_action, data=form_data)
                                    print("POST's data : ", form_data)

                                    # payload가 응답 텍스트에 포함되는지 확인되면,
                                    # 취약한 페이로드로 간주되어 vulnerable_urls 리스트에 추가
                                    if response.text is not None and payload.lower() in response.text.lower():
                                        vulnerable_urls.append(url)
                                        print(f"XSS 취약점이 발견된 URL (POST 방식): {url} 페이로드: {payload}")

        if vulnerable_urls:
            print(f"XSS 공격에 성공한 페이로드 개수: {len(vulnerable_urls)}")
            vulnerabilities.extend(vulnerable_urls)
        else:
            print("XSS 취약점이 발견되지 않았습니다.")

        logger.info("Finished XSS detection.")

    except RequestException as e:
        print(f"Error during HTTP request: {e}")