from django.urls import path
from .views.general.main_page import main_page
from .views.general.result_page import result_page
from .views import *
from .views.pdf_result.pdf_result import send_result
from .views.pdf_result.pdf_result import download_result
from .views.pdf_result.pdf_result import send_result_gpt
from .views.pdf_result.pdf_result import download_result_gpt
from .views.detection.code_analysis import code_analysis
#from .views import generate_pdf

urlpatterns = [
    path('', main_page, name='main_page'),
    path('result/', result_page, name='result_page'),
    path('download/', download_result, name='download_result'),
    path('code_analysis/', code_analysis, name='code_analysis'),
    # path('generate_pdf/', generate_pdf, name='generate_pdf'), 세이 pdf출력시 썼던 거
    path('send_result/', send_result, name='send_result'), #이메일 전송 관련
    path('send_result_gpt/', send_result_gpt, name='send_result_gpt'), #이메일 전송 관련_gpt
    path('download_gpt/', download_result_gpt, name='download_result_gpt'),
    #path('code_analysis_report/', views.code_analysis_report, name='code_analysis'),
]