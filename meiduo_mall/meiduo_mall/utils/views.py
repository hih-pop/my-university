from django import http
from django.contrib.auth.decorators import login_required

from meiduo_mall.utils.response_code import RETCODE


def login_required_json(view_func):
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            return view_func(request, *args, **kwargs)
        else:
            return http.JsonResponse({'code':RETCODE.SESSIONERR,
                                      'errmsg':'用户未登录'})
    return wrapper







class LoginRequiredMixin(object):
    @classmethod
    def as_view(cls,*args,**kwargs):
        view = super().as_view(*args,**kwargs)
        return login_required(view)

class LoginRequiredJsonMixin(object):
    @classmethod
    def as_view(cls,*args,**kwargs):
        view = super().as_view(*args,**kwargs)
        return login_required_json(view)