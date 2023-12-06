from django.shortcuts import render
from django.http import FileResponse, HttpResponse, JsonResponse
from datetime import datetime
import time
from .crawl_scan import *
from ..general.main_page import update_global_context


def result_page(request):
    if request.method == 'POST':
        now = datetime.now()
        start_time = time.time()  # 함수 실행 시작 시간 기록
        global url
        url = request.POST.get('url')
        options = request.POST.getlist('option')


        xss_vulnerabilities, sql_vulnerabilities = [], []
        directory_vulnerabilities, csrf_vulnerabilities = [], []
        
        # 쓰레드를 저장할 리스트
        threads = []
        if "전체" in options or "XSS" in options or "SQL Injection" in options or "CSRF" in options:
            xss_vulnerabilities, sql_vulnerabilities, csrf_vulnerabilities = crawl_and_scan(url, options)

        if "전체" in options or "Directory Indexing" in options:
            directory_vulnerabilities = no_crawl(url, options)


        # crawl_and_scan 함수에서 SQL 인젝션과 XSS 공격 실행
        #xss_vulnerabilities, sql_vulnerabilities = crawl_and_scan(url, options)
        #directory_vulnerabilities, csrf_vulnerabilities = no_crawl(url, options)
        set_xss_vulnerabilities = set(xss_vulnerabilities)
        set_xss_vulnerabilities = list(set_xss_vulnerabilities)
        set_sql_vulnerabilities = set(sql_vulnerabilities)
        set_sql_vulnerabilities = list(set_sql_vulnerabilities)
        set_csrf_vulnerabilities = set(csrf_vulnerabilities)
        set_csrf_vulnerabilities = list(set_csrf_vulnerabilities)

        # 결과 확인
        xss_detected = bool(xss_vulnerabilities)
        sql_injection_detected = bool(sql_vulnerabilities)
        directory_indexing_detected = bool(directory_vulnerabilities)
        csrf_detected = bool(csrf_vulnerabilities)

        print(f"[Results for {url}]")
        print("SQL Injection Detected:", sql_injection_detected)
        print("XSS Detected:", xss_detected)
        print("Directory Indexing:", directory_indexing_detected)
        print("CSRF:", csrf_detected)

        law1, law2, law3, law4, law5, law6, law7 = False, False, False, False, False, False, False

        check1 = request.POST.get('infoCollection')
        subcheck1 = request.POST.get('safetyMeasure')
        check2 = request.POST.get('processResidentNumber')
        subcheck2_1 = request.POST.get('caseUnderArticle24_2')
        subcheck2_2 = request.POST.get('residentNumberEncryption')
        subcheck2_3 = request.POST.get('allowMembershipWithoutResidentNumber')
        check3 = request.POST.get('accessLimit')
        check4 = request.POST.get('passwordEncryption')
        check5 = request.POST.get('dmzStorage')
        subcheck5 = request.POST.get('dmzEncrypt')
        check6 = request.POST.get('internalNetwork')
        subcheck6_1 = request.POST.get('internalEncrypt')
        subcheck6_2 = request.POST.get('riskAnalysis')
        check7 = request.POST.get('riskCalculation')
        subcheck7_1 = request.POST.get('caseUnderArticle71')
        subcheck7_2 = request.POST.get('caseUnderArticle72')
        subcheck7_3 = request.POST.get('caseUnderArticle73')

        private_file_score = 1
        law_score = 1

        if (xss_detected or sql_injection_detected or directory_indexing_detected or csrf_detected):
            law1 = True
        
        if check1 == 'yes' and subcheck1 == 'no':
            law2 = True

        if check2 == 'yes':
            if subcheck2_1 == 'no':
                law3 = True
            if subcheck2_2 == 'no':
                law4 = True
            if subcheck2_3 == 'no':
                law5 = True
        
        if check3 == 'no' or check4 == 'no':
            law6 = True
        
        if check4 == 'no':
            law7 = True
        elif check5 == 'yes' and subcheck5 == 'no':
            law7 = True
        elif check6 == 'yes':
            if subcheck6_1 == 'no' and subcheck6_2 == 'no':
                law7 = True
        
        if law1 or law2 or law3 or law4 or law5 or law6 or law7:
            law_score = 1.5
        
        if check7 == 'yes':
            if subcheck7_1 == 'yes':
                private_file_score = 5
            elif subcheck7_2 == 'yes':
                private_file_score = 3
            else:
                private_file_score = 1

        score = private_file_score + (law_score * 2) * 2

        end_time = time.time()  # 함수 실행 종료 시간 기록
        result_elapsed_time = end_time - start_time  # 전체 함수 실행 시간 계산

        # 출력 또는 기록할 때에는 소수점 2자리까지 제한
        result_elapsed_time = round( result_elapsed_time, 2)

        # 각 쓰레드의 작업이 끝날 때까지 대기
        for thread in threads:
            thread.join()

        context = {
            'url': url, 
            'options': options,
            'xss_detected': xss_detected,  
            'sql_injection_detected': sql_injection_detected,  
            'directory_indexing_detected': directory_indexing_detected,
            'csrf_detected': set_csrf_vulnerabilities,
            'xss_vul_list': set_xss_vulnerabilities,
            'sql_vul_list': set_sql_vulnerabilities,
            'directory_vul_list': directory_vulnerabilities,
            'csrf_vul_list': set_csrf_vulnerabilities,
            'score': score,
            'law1': law1,
            'law2': law2,
            'law3': law3,
            'law4': law4,
            'law5': law5,
            'law6': law6,
            'law7': law7,
            'result_elapsed_time':  result_elapsed_time,
            'now': now,
        }

        update_global_context('url', url)
        update_global_context('options', options)
        update_global_context('xss_detected', xss_detected)
        update_global_context('sql_injection_detected', sql_injection_detected)
        update_global_context('directory_indexing_detected', directory_indexing_detected)
        update_global_context('csrf_detected', csrf_detected)
        update_global_context('xss_vul_list', set_xss_vulnerabilities)
        update_global_context('sql_vul_list', set_sql_vulnerabilities)
        update_global_context('csrf_vul_list', set_csrf_vulnerabilities)
        update_global_context('directory_vul_list', directory_vulnerabilities)
        update_global_context('csrf_vul_list', csrf_vulnerabilities)
        update_global_context('score', score)
        update_global_context('law1', law1)
        update_global_context('law2', law2)
        update_global_context('law3', law3)
        update_global_context('law4', law4)
        update_global_context('law5', law5)
        update_global_context('law6', law6)
        update_global_context('law7', law7)
        update_global_context('result_elapsed_time', result_elapsed_time)
        update_global_context('now', now)

        print(context, request)

        return render(request, 'result.html', context)

    return HttpResponse("잘못된 요청입니다.", status=400)