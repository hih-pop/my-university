from django.conf import settings
from itsdangerous import TimedJSONWebSignatureSerializer
from meiduo_mall.utils import constants
from itsdangerous import BadData
import logging
logger = logging.getLogger('django')

def generate_access_token(openid):
    serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                 expires_in=constants.ACCESS_TOKEN_EXPIRES)
    data = {'openid':openid}
    # token 为二进制

    access_token = serializer.dumps(data)
    return access_token.decode()


def check_access_token(access_token):
    serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,

                                                 expires_in=constants.ACCESS_TOKEN_EXPIRES)

    try:

        data = serializer.loads(access_token)
    except BadData as e:
        logger.error(e)
        return None
    else:
        return data.get('openid')
