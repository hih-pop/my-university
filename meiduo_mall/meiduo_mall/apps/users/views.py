import json
import logging
import re

from django import http
from django.contrib.auth import login, authenticate, logout
from pymysql import DatabaseError
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from django_redis import get_redis_connection

from meiduo_mall.utils.response_code import RETCODE
from meiduo_mall.utils.views import LoginRequiredMixin, LoginRequiredJsonMixin
from users.models import Address, User

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

    def put(self, request, send_verify_email=None):
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



        addresses = Address.objects.filter(user=request.user, is_deleted=False)

        # 创建空的列表
        address_dict_list = []
        # 遍历
        for address in addresses:
            address_dict = {
                "id": address.id,
                "title": address.title,
                "receiver": address.receiver,
                "province": address.province.name,
                "city": address.city.name,
                "district": address.district.name,
                "place": address.place,
                "mobile": address.mobile,
                "tel": address.tel,
                "email": address.email
            }
            # 将默认地址移动到最前面
            default_address = request.user.default_address
            if default_address.id == address.id:
                # 查询集 addresses 没有 insert 方法
                address_dict_list.insert(0, address_dict)
            else:
                address_dict_list.append(address_dict)

        context = {
            'default_address_id': request.user.default_address_id,
            'addresses': address_dict_list,
        }

        return render(request, 'user_center_site.html', context)


class CreateAddressView(LoginRequiredJsonMixin,View):

    def post(self,request):

        # count = Address.objects.filter(is_deleted=False).count()
        count = request.user.addresses.filter(is_deleted=False).count()
        if count >= 20:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR,
                                      'errmsg':'超过地址数量上限'})

        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        if not all([receiver,province_id,city_id,district_id,place,mobile]):

            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')

        try:
            address = Address.objects.create(user=request.user,
                                             title=receiver,
                                             receiver=receiver,
                                             province_id=province_id,
                                             city_id=city_id,
                                             district_id=district_id,
                                             place=province_id,
                                             mobile=mobile,
                                             tel=tel,
                                             email=email)
            if not request.user.default_address:
                request.user.default_address = address
                request.user.save()


        except Exception as e:
            return http.JsonResponse({'code':RETCODE.DBERR,'errmsg':'地址添加失败'})
        address_data = {'title':receiver,
                         'receiver':receiver,
                         'province_id':province_id,
                         'city_id':city_id,
                         'district_id':district_id,
                         'place':province_id,
                         'mobile':mobile,
                         'tel':tel,
                         'email':email}
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'ok',
                                  'address':address_data})


class UpdateDestroyAddressView(LoginRequiredJsonMixin,View):


    def put(self,request,address_id):

        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        if not all([receiver,province_id,city_id,district_id,place,mobile]):

            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')
        try:
            Address.objects.filter(id=address_id).update(user=request.user,
                                                         title=receiver,
                                                         receiver=receiver,
                                                         province_id=province_id,
                                                         city_id=city_id,
                                                         district_id=district_id,
                                                         place=province_id,
                                                         mobile=mobile,
                                                         tel=tel,
                                                         email=email)
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,
                                      'errmsg':'数据库保存错误'})
        address = Address.objects.get(id=address_id)
        address_dict = {
                        "id": address.id,
                        "title": address.title,
                        "receiver": address.receiver,
                        "province": address.province.name,
                        "city": address.city.name,
                        "district": address.district.name,
                        "place": address.place,
                        "mobile": address.mobile,
                        "tel": address.tel,
                        "email": address.email
                    }
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'ok',
                                  'address':address_dict})


    def delete(self,request,address_id):

        try:
            address = Address.objects.get(id=address_id)
            address.is_deleted = True
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,
                                      'errmsg':'删除地址失败'})
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'删除数据成功'})


class DefaultAdddressView(LoginRequiredJsonMixin,View):

    def put(self,request,address_id):
        try:

            address = Address.objects.get(id=address_id)
            request.user.default_address = address
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,
                                      'errmsg':'修改默认地址失败'})
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'修改成功'})


class UpdatteTitleAddressView(LoginRequiredJsonMixin,View):

    def put(self,request,address_id):
        json_dict = json.loads(request.body.decode())
        title = json_dict.get('title')

        try:
            address = Address.objects.get(id=address_id)
            address.title = title
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,
                                      'errmsg':'更新标题失败'})
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'标题修改成功'})


class ChangePasswordView(LoginRequiredMixin,View):

    def get(self,request):

        return render(request,'user_center_pass.html')
    def post(self,request):

        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        new_password2 = request.POST.get('new_password2')

        if not all([old_password,new_password,new_password2]):
            return http.HttpResponseForbidden('缺少必传参数')
        try:
            result = request.user.check_password(old_password)
            if not result:
                raise Exception
        except Exception as e:
            return render(request,'user_senter_pass',{'origin_pwd_errmsg':'原始密码错误'})
        if not re.match(r'^[a-zA-Z0-9]{8,20}$',new_password):
            return http.HttpResponseForbidden('密码格式错误')


        if new_password != new_password2:
            return http.HttpResponseForbidden('两次输入不相同')
        try:
            request.user.set_password(new_password)
            request.user.save()
        except Exception as e:
            logger.error(e)
            return render(request,'user_center_pass.html',{'change_pwd_errmsg':'密码修改失败'})
        logout(request)
        response = redirect(reverse('users:login'))
        response.delete_cookie('username')
        return response
