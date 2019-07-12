import re

from django import http
from django.contrib.auth import login
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View
from django_redis import get_redis_connection
from pymysql import DatabaseError

from users.models import User


class RegisterView(View):
    def get(self,request):

        return render(request,'register.html')
    def post(self,request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')
        allow = request.POST.get('allow')
        sms_code_client = request.POST.get('sms_code')
        # 判断参数是否齐全
        if not all([username,password,password2,mobile,allow,sms_code_client]):
            return http.HttpResponseForbidden("缺少必传参数")
        # 判断用户名是否是5-20个字符

        if not re.match(r'^[a-zA-Z0-9]{5,20}$',username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')
        # 判断密码长度
        if not re.match(r'^[a-zA-Z0-9]{8,20}$',password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断两次密码是否一致
        if password != password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')
        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')
        conn = get_redis_connection('verify_code')
        sms_code = conn.get('sms_code%s' % mobile)
        if sms_code is None:
            return http.HttpResponseForbidden('验证码过期')
        sms_code_server = sms_code.decode()
        if sms_code_client != sms_code_server:
            return http.HttpResponseForbidden('验证码输入有误')

        try:
            user = User.objects.create_user(username=username,password=password,mobile=mobile)
        except DatabaseError:
            return render(request,'register.html',{'register_errmsg': '注册失败'})

        login(request, user)

        return redirect(reverse('contents:index'))
class UsernameCountView(View):
    def get(self,request,username):
        count = User.objects.filter(username=username).count()
        return http.JsonResponse({'code':0, 'errmsg': 'OK', 'count': count})


class MobileCountView(View):
    def get(self,request,mobile):
        count = User.objects.filter(mobile=mobile).count()
        return http.JsonResponse({'code':0,'errmsg':'OK','count':count})



class LoginView(View):
    def get(self,request):

        return render(request,'login.html')
    def post(self,request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')
        if not all([username, password, remembered]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}',username):
            return http.HttpResponseForbidden('请输入正确的用户名或手机号')
        if not re.match(r'^[a-zA-Z0-9]{8,20}',password):
            return http.HttpResponseForbidden('密码输入错误')
        user = User.objects.filter(username=username,password=password)
        if user is None:
            return render(request,'login.html',{'account_errmsg':'用户名或密码错误'})
