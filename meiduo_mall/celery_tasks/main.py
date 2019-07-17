import os
# 环境
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "meiduo_mall.settings.dev")

from celery import Celery



celery_app = Celery("meiduo")


celery_app.config_from_object('celery_tasks.config')
celery_app.autodiscover_tasks(['celery_tasks.sms','celery_tasks.email'])