from django import http
from django.core.cache import cache
from django.shortcuts import render
import logging
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






