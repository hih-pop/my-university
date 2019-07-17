from celery_tasks.main import celery_app

# bind：保证task对象会作为第一个参数自动传入
# name：异步任务别名
# retry_backoff：异常自动重试的时间间隔 第n次(retry_backoff×2^(n-1))s
# max_retries：异常自动重试次数的上限
from celery_tasks.yuntongxun.ccp_sms import CCP


@celery_app.task(bind = True,name = 'ccp_send_sms_code',retry_backoff = 3)
def ccp_send_sms_code(self,mobile,sms_code):


    # try:
    result = CCP().send_template_sms(mobile,[sms_code,5],1)

    # except Exception as e:
    #     raise self.retry(exc=e,max_retries=3)
    # if result != 0:
    #     raise self.retry(exc='发送彻底失败',max_retries=3)


    return result


