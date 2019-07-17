from celery_tasks.email.tasks import send_verify_email
import json
import re

from django import http
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect


from meiduo_mall.utils.response_code import RETCODE
# Create your views here.
from django.urls import reverse
from django.views import View
from django_redis import get_redis_connection
from pymysql import DatabaseError

from users.models import User

from meiduo_mall.utils.views import LoginRequiredMixin, LoginRequiredJsonMixin
import logging
logger = logging.getLogger('django')

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
        sms_code_server = conn.get('sms_code_%s' % mobile)
        if sms_code_server is None:
            return http.HttpResponseForbidden('短信验证码过期')
        if sms_code_client != sms_code_server.decode():
            return http.HttpResponseForbidden('验证码输入有误')

        try:
            user = User.objects.create_user(username=username,password=password,mobile=mobile)
        except DatabaseError:
            return render(request,'register.html',{'register_errmsg': '注册失败'})

        login(request, user)

        response = redirect(reverse('contents:index'))
        response.set_cookie('username', user.username, max_age=3600 * 24 * 14)
        return response


class UsernameCountView(View):
    def get(self,request,username):
        count = User.objects.filter(username=username).count()
        return http.JsonResponse({'code':0, 'errmsg': 'OK', 'count': count})


class MobileCountView(View):
    def get(self,request,mobile):
        count = User.objects.filter(mobile=mobile).count()
        return http.JsonResponse({'code':RETCODE.OK,'errmsg':'OK','count':count})


class LoginView(View):
    def get(self,request):

        return render(request,'login.html')
    def post(self,request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')
        if not all([username, password]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}',username):
            return http.HttpResponseForbidden('请输入正确的用户名或手机号')
        if not re.match(r'^[a-zA-Z0-9]{8,20}',password):
            return http.HttpResponseForbidden('密码输入错误')
        user = authenticate(username=username, password=password)
        if user is None:
            return render(request,'login.html',{'account_errmsg':'用户名或密码错误'})
        login(request,user)
        if remembered != 'on':
            request.session.set_expiry(0)
        else:
            request.session.set_expiry(None)


        # response = redirect(reverse('contents:index'))
        # response.set_cookie('username',user.username,max_age=3600*24*14)
        # return response
        # 接受变量
        next = request.GET.get('next')
        if next:
            response = redirect('next')
        else:
            response = redirect(reverse('contents:index'))
        response.set_cookie('username',user.username,max_age=3600*24*14)
        return response


class LogoutView(View):

    '''推出登陆'''
    def get(self,request):
        '''
        实现推出登陆逻辑
        :param request:
        :return:
        '''
        logout(request)
        # 重定向到首页
        response = redirect(reverse('contents:index'))
        # 清除cookie中username
        response.delete_cookie('username')
        return response


class UserInfoView(LoginRequiredMixin,View):

    def get(self,request):


        context = {
            'username':request.user.username,
            'mobile':request.user.mobile,
            'email':request.user.email,
            'email_active':request.user.email_active
        }
        return render(request,'user_center_info.html',context)


class EmailView(LoginRequiredJsonMixin,View):

    def put(self,request):
        json_dict = json.loads(request.body.decode())
        email = json_dict.get('email')
        if not email:
            return http.HttpResponseForbidden('缺少email参数')
        if not re.match(r'^[a-z0-9_][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$',email):
            return http.HttpResponseForbidden('email格式错误')
        # 赋值 email 字段
        try:
            request.user.email = email
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '添加邮箱失败'})

        # 导入:
        # 异步发送验证邮件
        # 用定义好的函数替换原来的字符串:
        verify_url = request.user.generate_verify_email_url()
        # 发送验证链接:
        send_verify_email.delay(email, verify_url)
        # 响应添加邮箱结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '添加邮箱成功'})


class VerifyEmailView(LoginRequiredMixin,View):
    """验证邮箱"""

    def get(self, request):
        """实现邮箱验证逻辑"""
        # 接收参数
        token = request.GET.get('token')

        # 校验参数：判断 token 是否为空和过期，提取 user
        if not token:
            return http.HttpResponseBadRequest('缺少token')

        # 调用上面封装好的方法, 将 token 传入
        user = User.check_verify_email_token(token)
        if not user:
            return http.HttpResponseForbidden('无效的token')

        # 修改 email_active 的值为 True
        try:
            user.email_active = True
            user.save()
        except Exception as e:
            logger.error(e)
            return http.HttpResponseServerError('激活邮件失败')

        # 返回邮箱验证结果
        return redirect(reverse('users:info'))

class AddressView(LoginRequiredMixin, View):
    """用户收货地址"""

    def get(self, request):
        """提供收货地址界面"""
        return render(request, 'user_center_site.html')












