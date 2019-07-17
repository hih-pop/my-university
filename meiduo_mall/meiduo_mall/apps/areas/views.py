import json
import re

from django import http
from django.core.cache import cache
from django.shortcuts import render
import logging

from meiduo_mall.utils.views import LoginRequiredMixin
from users.models import Address

logger = logging.getLogger('django')

# Create your views here.
from django.views import View

from areas.models import Area
from meiduo_mall.utils.response_code import RETCODE


class ProvinceAreasView(View):

    def get(self,rquest):
        province_list = cache.get('province_list')
        if not province_list:




            try:
                province_model_list = Area.objects.filter(parent__isnull=True)
                province_list = []
                for province_model in province_model_list:
                    province_list.append({'id':province_model.id,
                                        'name':province_model.name })

                cache.set('province_list',province_list,3600)
            except Exception as e:
                logger.error(e)
                return http.JsonResponse({'code':RETCODE.DBERR,
                                      'errmsg':'省份信息错误'})

        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'ok',
                                  'province_list':province_list})


class SubAreasView(View):

    def get(self,request,pk):
        sub_data = cache.get('sub_data_'+pk)
        if not sub_data:

            try:

                province_model = Area.objects.get(id=pk)
                sub_model_list = Area.objects.filter(parent=pk)

                subs = []
                for sub_model in sub_model_list:
                    subs.append({'id':sub_model.id,
                                 'name':sub_model.name})

                sub_data = {'id':province_model.id,
                            'name':province_model.name,
                            'subs':subs}
                cache.set('sub_data_'+pk,sub_data,3600)
            except Exception as e:
                return http.JsonResponse({'code':RETCODE.DBERR,
                                          'errmsg':'获取数据失败'})
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'ok',
                                  'sub_data':sub_data})


class CreateAddressView(LoginRequiredMixin,View):

    def post(self,request):

        count = Address.objects.filter(user=request.user).count()
        if count > 20:
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

