import requests
from bs4 import BeautifulSoup
import urllib.parse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def directory_indexing_detection(url, vulnerabilities):

    logger.info("Starting Directory Indexing detection...")

    fname = "blog/payloads/directory_index.txt"
    with open(fname) as f:
        payloads = [x.strip() for x in f.readlines()]
    
    parsed_url = urllib.parse.urlparse(url)
    scheme = parsed_url.scheme
    domain = parsed_url.netloc

    vul_url_list = google_search(domain, 2)

    for payload in payloads:
        dectect_url = f"{scheme}://{domain}{payload}"
        if dectect_url in vul_url_list:
                print('dork 방식으로 탐지함')
        else:
            response = requests.get(dectect_url)

            if 'index of' in response.text.lower():
                vul_url_list.append(dectect_url)

    if vul_url_list:
        print(f'Diectory Indexing 취약점이 탐지된 url 개수: {len(vul_url_list)}')
        vulnerabilities.extend(vul_url_list)

    else:
        return []
    logger.info("Finished Directory Indexing detection.")

def google_search(url, page):
    base_url = 'https://www.google.com/search'
    headers  = { 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0' }
    result = []
    query = f'intitle:index of site:{url}'

    for p in range(page):
        params   = { 'q': query, 'page': p * 10 }
        resp = requests.get(base_url, params=params, headers=headers)
        soup = BeautifulSoup(resp.text, 'html.parser')
        print(resp.status_code)

        links = soup.findAll("div", { "class" : "yuRUbf" })
        #links = bsoup.findAll('a')
        # print(links)
        for link in links:
            l = link.find('a').get('href')
            if not l in result:
                result.append(l)
    
    return result