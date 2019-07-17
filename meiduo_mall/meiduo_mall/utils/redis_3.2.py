from redis import Redis
from django.conf import settings

class MyDjangoRedis3(Redis):

    def get(self, name):
        """
        重写get()方法,因为Redis类中的get()返回的是二进制数据,我需要的是str类型的数据
        :param name: 键
        :return: 值(str)
        """
        value = self.execute_command('GET', name)

        if not value:
            return None

        return str(value,encoding="utf8")


redis3 = MyDjangoRedis3(
    host=settings.MY_CACHES_3["HOST"],
    port=settings.MY_CACHES_3["PORT"],
    db=settings.MY_CACHES_3["DB"],
)

# host = 'localhost', port = 6379,
# db = 0, password = None, socket_timeout = None,
# socket_connect_timeout = None,
# socket_keepalive = None, socket_keepalive_options = None,
# connection_pool = None, unix_socket_path = None,
# encoding = 'utf-8', encoding_errors = 'strict',
# charset = None, errors = None,
# decode_responses = False, retry_on_timeout = False,
# ssl = False, ssl_keyfile = None, ssl_certfile = None,
# ssl_cert_reqs = 'required', ssl_ca_certs = None,
# max_connections = None
