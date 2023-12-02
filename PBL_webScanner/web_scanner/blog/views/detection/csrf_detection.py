import requests
from bs4 import BeautifulSoup
import re
import logging
from pathlib import Path
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def strength(string):
    digits = re.findall(r'\d', string)
    lowerAlphas = re.findall(r'[a-z]', string)
    upperAlphas = re.findall(r'[A-Z]', string)
    entropy = len(set(digits + lowerAlphas + upperAlphas))
    if not digits:
        entropy = entropy/2
    return entropy

def csrf_detection(url, vulnerabilities):
    logger.info("Starting CSRF detection...")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_vul_url_list = []
        csrf_token = None

        # 폼 요소를 찾아 CSRF 토큰 추출
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                if 'token' in input_name:
                    csrf_token = input_field.get('value')
                    break  # 토큰을 찾으면 루프 종료

        if csrf_token and re.match(r'^[\w\-_]+$', csrf_token):
            print(f"CSRF Token Found: {csrf_token}")
            if(strength(csrf_token)>20):
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
                    print("취약한 토큰입니다. 토큰이 만들어진 해시함수 : %s\n",matches)
                    csrf_vul_url_list.append(url)
                else:
                    print("견고한 토큰입니다.")
            else:
                print("취약한 토큰입니다. 토큰이 만들어진 해시함수: %s",matches)
                csrf_vul_url_list.append(url)

        else:
            print("csrf토큰이 없습니다.")


        if csrf_vul_url_list:
            print(f'CSRF 취약점이 탐지된 url 개수: {len(csrf_vul_url_list)}')
            vulnerabilities.extend(csrf_vul_url_list)
        else:
            return []

        logger.info("Finished CSRF detection.")

    except Exception as e:
        print(f"Error: {e}")