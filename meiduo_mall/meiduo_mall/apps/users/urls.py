"""meiduo_mall URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib.auth.decorators import login_required

from . import views


urlpatterns = [
    # 注册
    url(r'^register/$',views.RegisterView.as_view(), name='register'),
    # 用户名
    url(r'^usernames/(?P<username>\w{5,20})/count/$',views.UsernameCountView.as_view()),
    # 手机号
    url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$',views.MobileCountView.as_view()),
    # 登陆
    url(r'^login/$',views.LoginView.as_view(),name='login'),
    # 推出
    url(r'^logout/$',views.LogoutView.as_view(),name='logout'),
    # 个人中心
    url(r'^info/$',views.UserInfoView.as_view(),name='info'),
    url(r'^emails/$',views.EmailView.as_view(),name='email'),
    url(r'^emails/verification/$',views.VerifyEmailView.as_view()),
    url(r'^addresses/$', views.AddressView.as_view(), name='addresses'),
    url(r'^addresses/create/$', views.CreateAddressView.as_view()),
    url(r'^addresses/(?P<address_id>\d+)/$', views.UpdateDestroyAddressView.as_view()),
    url(r'^addresses/(?P<address_id>\d+)/default/$',views.DefaultAdddressView.as_view(),),
    url(r'^addresses/(?P<address_id>\d+)/title/$',views.UpdatteTitleAddressView.as_view()),
    url(r'^password/$', views.ChangePasswordView.as_view(), name='pass'),
]
