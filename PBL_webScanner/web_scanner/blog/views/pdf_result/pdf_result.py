from django.templatetags.static import static
from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from django.http import FileResponse, HttpResponse, JsonResponse
from django.template.loader import get_template
from io import BytesIO
from weasyprint import HTML, CSS
from ..general.main_page import global_context



def download_result(request):
    # report.html을 렌더링하여 HTML 문자열을 얻습니다.
    template = get_template('report.html')
    html_string = template.render(global_context, request=request)

    # CSS 파일의 URL을 생성합니다.
    css_url = request.build_absolute_uri(static('css/report_style.css'))

    # HTML 문자열을 WeasyPrint를 사용하여 PDF로 변환합니다. 이 때 CSS를 적용합니다.
    pdf_file = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf(stylesheets=[CSS(css_url)])

    # PDF 파일을 HttpResponse로 반환하여 브라우저에서 열도록 합니다.
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="report.pdf"'

    return response

def download_result_gpt(request):
    # report.html을 렌더링하여 HTML 문자열을 얻습니다.
    template = get_template('coderesultreport.html')
    html_string = template.render(global_context, request=request)

    # CSS 파일의 URL을 생성합니다.
    css_url = request.build_absolute_uri(static('css/report_style.css'))

    # HTML 문자열을 WeasyPrint를 사용하여 PDF로 변환합니다. 이 때 CSS를 적용합니다.
    pdf_file = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf(stylesheets=[CSS(css_url)])

    # PDF 파일을 HttpResponse로 반환하여 브라우저에서 열도록 합니다.
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="report.pdf"'

    return response

def send_result(request):
    # report.html을 렌더링하여 HTML 문자열을 얻습니다.
    template = get_template('report.html')
    html_string = template.render(global_context, request=request)

    # CSS 파일의 URL을 생성합니다.
    css_url = request.build_absolute_uri(static('css/report_style.css'))

    # HTML 문자열을 WeasyPrint를 사용하여 PDF로 변환합니다. 이 때 CSS를 적용합니다.
    pdf_file = BytesIO()
    HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf(pdf_file, stylesheets=[CSS(css_url)])

    # 이메일 주소를 가져옵니다.
    email = request.POST.get('email')  # POST로 변경

    if email:
        # 이메일을 전송합니다.
        subject = 'SWU_CANNER 보고서'
        message = '안녕하세요. 떡잎마을 방범대입니다.\n\n\n'
        message += 'SWU_CANNER의 결과 전송해드립니다.\n'
        message += '첨부된 보고서를 확인해주세요.'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        email_message = EmailMessage(subject, message, from_email, recipient_list)
        email_message.attach('report.pdf', pdf_file.getvalue(), 'application/pdf')

        try:
            email_message.send()
            print("이메일이 성공적으로 전송되었습니다.")
        except Exception as e:
            print("이메일 전송에 실패했습니다. 에러:", str(e))
            # 실패한 경우 어떤 처리를 할지 여기에 추가할 수 있습니다.

        return HttpResponse("이메일이 성공적으로 전송되었습니다.", status=200)

    return HttpResponse("잘못된 요청입니다.", status=400)

def send_result_gpt(request):
    # report.html을 렌더링하여 HTML 문자열을 얻습니다.
    template = get_template('coderesultreport.html')
    html_string = template.render(global_context, request=request)

    # CSS 파일의 URL을 생성합니다.
    css_url = request.build_absolute_uri(static('css/report_style.css'))

    # HTML 문자열을 WeasyPrint를 사용하여 PDF로 변환합니다. 이 때 CSS를 적용합니다.
    pdf_file = BytesIO()
    HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf(pdf_file, stylesheets=[CSS(css_url)])

    # 이메일 주소를 가져옵니다.
    email = request.POST.get('email')  # POST로 변경

    if email:
        # 이메일을 전송합니다.
        subject = 'SWU_CANNER 보고서'
        message = '안녕하세요. 떡잎마을 방범대입니다.\n\n\n'
        message += 'SWU_CANNER의 결과 전송해드립니다.\n'
        message += '첨부된 보고서를 확인해주세요.'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        email_message = EmailMessage(subject, message, from_email, recipient_list)
        email_message.attach('report.pdf', pdf_file.getvalue(), 'application/pdf')

        try:
            email_message.send()
            print("이메일이 성공적으로 전송되었습니다.")
        except Exception as e:
            print("이메일 전송에 실패했습니다. 에러:", str(e))
            # 실패한 경우 어떤 처리를 할지 여기에 추가할 수 있습니다.

        return HttpResponse("이메일이 성공적으로 전송되었습니다.", status=200)

    return HttpResponse("잘못된 요청입니다.", status=400)