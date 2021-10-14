import fastapi_jwt_auth
import base64
import hmac
import json
import asyncio
import functools
from contextlib import contextmanager

from fastapi import Depends
from helper.config import config, AUTH_EXCEPTION
from fastapi_jwt_auth import AuthJWT
from datetime import timedelta
from redis import Redis
from pydantic import BaseModel
from redis import Redis


redis_conn = Redis(host='localhost', port=6379, db=0, decode_responses=True)


class Settings(BaseModel):
    authjwt_secret_key:str = config['SECRET_KEY']
    authjwt_denylist_enabled:bool = True
    authjwt_denylist_token_checks:set={'access', 'refresh'}
    access_expires:int = timedelta(minutes=30)
    refresh_expires: int = timedelta(days=30)


settings = Settings()
@AuthJWT.load_config
def get_config():
    return settings


@AuthJWT.token_in_denylist_loader
def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token['jti']
    entry = redis_conn.get(jti)
    return entry and entry == 'true'


def create_signed_token(key, data):
    headers = json.dumps({"typ": "JWT", 'alg': "HS256"}).encode('utf-8')
    henc = base64.urlsafe_b64encode(headers).decode().strip('=')

    payload = json.dumps(data).encode('utf-8')
    penc = base64.urlsafe_b64encode(payload).decode().strip('=')

    hdata = henc + '.' + penc
    d = hmac.new(key, hdata.encode('utf-8'), 'sha256')
    dig = d.digest()
    denc = base64.urlsafe_b64encode(dig).decode().strip('=')

    token = hdata + '.' + denc
    return token


def verify_signed_token(key, token):
    (header, payload, signature) = token.split('.')
    hdata = header + '.' + payload

    d = hmac.new(key, hdata.encode('utf-8'), 'sha256')
    dig = d.digest()
    denc = base64.urlsafe_b64encode(dig).decode().strip('=')

    verified = hmac.compare_digest(denc, signature)
    payload += '=' * (-len(payload) % 4)
    payload_data = json.loads(base64.urlsafe_b64decode(payload).decode())
    return (verified, payload_data)


def decorate_sync_async(decorating_context, func):
    if asyncio.iscoroutinefunction(func):
        async def decorated(Authorize:AuthJWT=Depends(), *args, **kwargs):
            with decorating_context(Authorize):
                return (await func(Authorize, *args, **kwargs))
    else:
        def decorated(Authorize:AuthJWT=Depends(), *args, **kwargs):
            with decorating_context(Authorize):
                return func(Authorize, *args, **kwargs)

    return functools.wraps(func)(decorated)


@contextmanager
def wrapper(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_required()
    except fastapi_jwt_auth.exceptions.MissingTokenError as e:
        raise AUTH_EXCEPTION
    except fastapi_jwt_auth.exceptions.RevokedTokenError as e:
        raise AUTH_EXCEPTION
    yield


def validate_token(func, Authorize:AuthJWT=Depends()):
    context = lambda Authorize: wrapper(Authorize)
    return decorate_sync_async(context, func)