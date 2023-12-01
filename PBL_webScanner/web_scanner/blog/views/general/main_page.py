from django.shortcuts import render
from datetime import datetime
import requests
import time
import logging



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def main_page(request):
    now = datetime.now()
    context = {
        "now": now
    }
    return render(request, 'main_page.html', context)

def headers_reader(url):
    try:
        response = requests.get(url)
        headers = response.headers
        print(" [+] Headers for " + url)
        for header, value in headers.items():
            print(f"  {header}: {value}")
        print("\n")
    except Exception as e:
        print(" [!] Error reading headers:", e)



def measure_execution_time(func, *args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    elapsed_time = end_time - start_time
    return result, elapsed_time

global_context = {}
  
# 함수에서 딕셔너리 업데이트
def update_global_context(key, value):
    global global_context
    global_context[key] = value  





