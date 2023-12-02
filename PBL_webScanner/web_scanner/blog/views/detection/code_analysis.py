from datetime import datetime
import openai
from django.shortcuts import render
from datetime import datetime
from ..general.main_page import global_context
import os
from dotenv import load_dotenv

load_dotenv() 


def code_analysis(request):

    code = request.POST.get('code')

    now2 = datetime.now()  # 현재 시간을 가져옵니다.

    openai.api_key = os.getenv('OPENAI_API_KEY')

    # 여러 개의 질문을 리스트로 정의
    questions = [
        "취약한 부분",
        "근거",
        "수정 방안"
    ]

    # 각 질문에 대한 응답을 저장할 리스트
    responses = []

    # 각 질문에 대해 ChatGPT에 요청하여 응답 받기
    for question in questions:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo", 
            messages=[
                {"role": "system", "content": "당신은 도움이 되는 비서입니다."},
                {"role": "user", "content": code},
                {"role": "user", "content": question},
            ]
        )
        
        # 응답에서 분석 결과 가져오기
        analysis = response['choices'][0]['message']['content']
        
        # 질문과 대한 응답을 저장
        responses.append({
            'question': question,
            'answer': analysis
        })

    # global_context에 responses와 now2 추가
    global_context.update({'responses': responses, 'now2': now2})

    return render(request, 'coderesult.html', {'responses': responses, 'now2': now2})

def some_view(request):
    # code_analysis 함수 호출
    responses, now2 = code_analysis(request)

    # coderesult.html에 table_html 전달
    return render(request, 'coderesult.html', {'responses': responses, 'now2': now2})

def some_other_view(request):
    # code_analysis 함수 호출
    responses, now2 = code_analysis(request)

    # coderesultreport.html에 table_html와 now 전달
    return render(request, 'coderesultreport.html', {'responses': responses, 'now2': now2})