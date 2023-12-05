import requests
from bs4 import BeautifulSoup
import re
import logging
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import json
from collections import Counter
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MIN_ENTROPY = 3

TOKEN_FORM_STRINGS = [
    "authenticity_token", "_token", "csrf_token", "csrfname", "csrftoken", "anticsrf",
    "__requestverificationtoken", "token", "csrf", "_csrf_token", "xsrf_token",
    "_csrf", "csrf-token", "xsrf-token", "_wpnonce", "csrfmiddlewaretoken",
    "__csrf_token__", "csrfkey"
]

TOKEN_HEADER_STRINGS = [
    "csrf-token", "x-csrf-token", "xsrf-token", "x-xsrf-token", "csrfp-token",
    "anti-csrf-token", "x-csrf-header", "x-xsrf-header", "x-csrf-protection"
]

# 얼마나 무작위하고 예측하기 어려운지, 암호화 키의 예측 불가능성을 평가
def entropy(string: str):
    probabilities = [n_x / len(string) for x, n_x in Counter(string).items()]
    e_x = [-p_x * math.log(p_x, 2) for p_x in probabilities]
    return sum(e_x)

# 문자열의 "강도"를 계산, CSRF 토큰의 강도를 판단하는 경우
def strength(string):
    digits = re.findall(r'\d', string)
    lowerAlphas = re.findall(r'[a-z]', string)
    upperAlphas = re.findall(r'[A-Z]', string)
    entropy = len(set(digits + lowerAlphas + upperAlphas))
    if not digits:
        entropy = entropy/2
    return entropy

def extract_csrf_token_from_headers(headers):
    # 헤더에서 CSRF 토큰 추출
    for csrf_header in TOKEN_HEADER_STRINGS:
        if csrf_header in headers:
            csrf_token = headers[csrf_header]
            return csrf_token
    return None

def csrf_detection(url, vulnerabilities):
    logger.info("Starting CSRF detection...")
    csrf_token = None
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # 폼 요소를 찾아 CSRF 토큰 추출
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                if any(token_string in input_name for token_string in TOKEN_FORM_STRINGS):
                    csrf_token = input_field.get('value')
                    break  # 토큰을 찾으면 루프 종료

        if not csrf_token:
            # 폼에서 찾지 못했으면 헤더에서 시도
            csrf_token = extract_csrf_token_from_headers(response.headers)

            if not csrf_token:
                # 헤더에서도 찾지 못하면 요청 헤더에서 시도
                csrf_token = extract_csrf_token_from_headers(response.request.headers)

            if not csrf_token:
                print("CSRF토큰이 없는 취약한 사이트입니다.")
                # vulnerabilities.extend(url)
                split_url = urlsplit(url)
                no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                vulnerabilities.append(no_query_url)

        elif csrf_token and re.match(r'^[\w\-_]+$', csrf_token):
            print(f"CSRF Token Found: {csrf_token}")
            # CSRF 토큰이 발견된 경우에 추가 검증 실행
            same_site_pattern = r'SameSite=(Strict|Lax)'
            match = re.search(same_site_pattern, response.headers.get('set-cookie', ''))
            if match:
                same_site_value = match.group(1)
                if same_site_value in ["Strict", "Lax"]:
                    print(f"SameSite 속성이 올바르게 설정되었습니다: {same_site_value}")
                else:
                    print(f"SameSite 속성이 설정되어 있지만, 올바르지 않은 값입니다: {same_site_value}")
                    split_url = urlsplit(url)
                    no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                    vulnerabilities.append(no_query_url)
                    return
            else:
                print("SameSite 속성이 설정되어 있지 않습니다.")
                split_url = urlsplit(url)
                no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                vulnerabilities.append(no_query_url)
                return
            
            if entropy(csrf_token) < MIN_ENTROPY:
                print(f"예측 가능한 취약한 토큰입니다 (Entropy: {entropy(csrf_token)})")
                split_url = urlsplit(url)
                no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                vulnerabilities.append(no_query_url)
            else:
                print(entropy(csrf_token))
                if strength(csrf_token) > 20:
                    print(strength(csrf_token))
                    p = Path(__file__).parent.joinpath('db/hashes.json')
                    with p.open('r') as f:
                        hashPatterns = json.load(f)

                    matches = []
                    for element in hashPatterns:
                        pattern = element['regex']
                        if re.match(pattern, csrf_token):
                            for name in element['matches']:
                                matches.append(name)
                    if matches:
                        split_url = urlsplit(url)
                        no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                        vulnerabilities.append(no_query_url)
                        print("토큰이 만들어진 해시함수가 예측되므로 취약한 토큰입니다. : {matches}")

                    else:
                        print("견고한 토큰입니다.")
                else:
                    print(f"문자열의 복잡성이 낮은 취약한 토큰입니다.")
                    split_url = urlsplit(url)
                    no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
                    vulnerabilities.append(no_query_url)

        logger.info("Finished CSRF detection.")

    except Exception as e:
        print(f"Error: {e}")