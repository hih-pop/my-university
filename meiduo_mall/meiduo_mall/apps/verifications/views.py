import random

from django import http

from meiduo_mall.libs.yuntongxun.ccp_sms import CCP
from meiduo_mall.utils import constants
from meiduo_mall.utils.response_code import RETCODE


from django.shortcuts import render
import logging
logger = logging.getLogger('django')

# Create your views here.
from django.views import View
from django_redis import get_redis_connection

from meiduo_mall.libs.captcha.captcha import captcha


class ImageCodeView(View):

    def get(self,request,uuid):
        # 生成图形验证码
        text,image = captcha.generate_captcha()

        # 打开redis "verify_code"库
        redis_conn = get_redis_connection('verify_code')
        # 将图形验证码保存到redis库中
        redis_conn.setex('img_%s' % uuid, constants.IMAGE_CODE_REDIS_EXPIRES, text)
        # 返回图形验证码
        return http.HttpResponse(image, content_type='imgae/jpg')


class SMSCodeView(View):

    def get(self,request,mobile):
        image_code_cilent = request.GET.get("image_code")
        uuid = request.GET.get("image_code_id")
        # 判断参数
        if not all([image_code_cilent,uuid]):
            return http.JsonResponse({'code':RETCODE.IMAGECODEERR,
                                      'errmsg':"缺少必传参数"})
        # 教研参数
        conn = get_redis_connection("verify_code")
        image_code = conn.get('img_%s' % uuid)
        if image_code is None:
            return http.JsonResponse({'code':RETCODE.IMAGECODEERR,
                                      'errmsg':"验证码过期"})
        try:
            conn.delete('img_%s' % uuid)
        except Exception as e:
            logger.error(e)
        image_code_server = image_code.decode()
        if image_code_cilent.lower() != image_code_server.lower():
            return http.JsonResponse({'code':RETCODE.IMAGECODEERR,
                                      'errmsg':"验证码错误"})
        # 生成验证码
        sms_code = '%06d'% random.randint(0,999999)
        print(sms_code)
        # 保存到redis
        conn.setex('sms_code%s' % mobile,constants.IMAGE_CODE_REDIS_EXPIRES,sms_code)
        # 发送验证码
        # CCP().send_template_sms(mobile,[sms_code,5],constants.SMS_CDDE_ID)
        return http.JsonResponse({'code':RETCODE.OK,
                                  'error':'ok'})





