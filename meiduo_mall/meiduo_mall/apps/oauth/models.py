from django.db import models
from meiduo_mall.utils.models import BaseModel

# Create your models here.
class OauthQQUser(BaseModel):
    user = models.ForeignKey('users.User',on_delete=models.CASCADE,
                             verbose_name='用户')
    openid = models.CharField(max_length=64,
                              db_index=True,
                              verbose_name='openid')
    class Meta:
        db_table = 'tb_oauth_qq'
        verbose_name = 'QQ登陆用户数据'
        verbose_name_plural = verbose_name

