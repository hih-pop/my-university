import re

from django import http
from django.conf import settings
from django.contrib.auth import login
from django.shortcuts import render, redirect
from QQLoginTool.QQtool import OAuthQQ
from django.urls import reverse
from django_redis import get_redis_connection

from meiduo_mall.utils.response_code import RETCODE


import logging

from oauth.models import OauthQQUser
from oauth.utils import check_access_token, generate_access_token
from users.models import User

logger = logging.getLogger('django')

# Create your views here.
from django.views import View


class QQURLView(View):
    """提供QQ登录页面网址
               https://graph.qq.com/oauth2.0/authorize?
               response_type=code&
               client_id=xxx&
               redirect_uri=xxx&
               state=xxx
               """


    def get(self,request):
        next = request.GET.get('next')
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                        client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI,
                        state=next)
        login_url = oauth.get_qq_url()
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'OK',
                                  'login_url':login_url})


class QQUserView(View):
    def get(self,request):
        code = request.GET.get('code')
        if not code:
            return http.HttpResponseForbidden("缺少code")
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                        client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI
                        )
        try:
            aaaaaccess_token = oauth.get_access_token(code)
            openid = oauth.get_open_id(aaaaaccess_token)
        except Exception as e:
            logger.error(e)
            return http.HttpResponseServerError('OAuth2.0认证失败')
        try:
            oauth_user = OauthQQUser.objects.get(openid = openid)
        except OauthQQUser.DoesNotExist:
            # 没有帮顶qq
            access_token = generate_access_token(openid)
            context = {'access_token':access_token}
            return render(request,'oauth_callback.html',context)

        else:
            qq_user = oauth_user.user
            login(request,qq_user)
            response = redirect(reverse('contents:index'))
            response.set_cookie('username',qq_user.username,max_age=3600*24*14)
            return response
    def post(self,request):
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        sms_code_client = request.POST.get('sms_code')
        access_token = request.POST.get('access_token')
        if not all([mobile,password,sms_code_client,access_token]):
            return http.HttpResponseForbidden('缺少必传参数')

            # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')

        # 判断密码是否合格
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')

        # 3.判断短信验证码是否一致
        # 创建 redis 链接对象:
        redis_conn = get_redis_connection('verify_code')
        # 从 redis 中获取 sms_code 值:
        sms_code_server = redis_conn.get('sms_code_%s' % mobile)
        # 判断获取出来的有没有:
        if sms_code_server is None:
            # 如果没有, 直接返回:
            return render(request, 'oauth_callback.html', {'sms_code_errmsg': '无效的短信验证码'})
        # 如果有, 则进行判断:
        if sms_code_client != sms_code_server.decode():
            # 如果不匹配, 则直接返回:
            return render(request, 'oauth_callback.html', {'sms_code_errmsg': '输入短信验证码有误'})
        # 调用我们自定义的函数, 检验传入的 access_token 是否正确:
        # 错误提示放在 sms_code_errmsg 位置
        openid = check_access_token(access_token)
        if openid is None:
            return render(request, 'oauth_callback.html', {'openid_errmsg': '无效的openid'})
        try:

            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            user = User.objects.create_user(username=mobile,password=password,mobile=mobile)
        if not user.check_password(password):
            return render(request,'oauth_callback.html',{'account_errmsg':'用户名或密码错误'})
        try:
            OauthQQUser.objects.create(openid=openid,user=user)
        except Exception as e:
            return render(request, 'oauth_callback.html', {'qq_lorin_errmsg': '帮顶失败'})
        login(request,user)


        next = request.GET.get('state')
        response = redirect(next)
        response.set_cookie('username',user.username,max_age=3600*24*14)
        return response








