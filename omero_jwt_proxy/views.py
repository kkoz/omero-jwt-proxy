# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

import jwt
from jwt.algorithms import RSAAlgorithm
import json
from datetime import datetime, timedelta
import logging
import requests
import base64

from omero_connection_manager import OmeroConnectionManager


log = logging.getLogger('jwtproxy')
log.setLevel('INFO')

RCSVC_KEY = 'test_secret_123'

DEFAULT_GROUPNAME = 'test_group'

omero_manager = OmeroConnectionManager()


def get_jwt_form_header(request):
    return request.META['HTTP_AUTHORIZATION'].split(' ')[1]

def index(request):
    jwt = get_jwt_form_header(request)
    print(jwt)
    log.info(jwt)
    return HttpResponse("Hello! You have reached the jwt-proxy index")

def get_url_from_session_uuid(session_uuid):
    return 'http://localhost:4080/webclient?bsession=' + session_uuid + '&server=1'

def get_session(username, firstname='firstname', lastname='lastname'):
    omero_manager.create_or_update_user(firstname,
        lastname,
        username,
        'test',
        DEFAULT_GROUPNAME,
        is_admin=False)
    session = omero_manager.create_session_with_timeout(username,
                                                        groupname,
                                                        timeout=600000)
    return session

def get_user_info_from_rcsvc(user_id):
    rcsvc_jwt = jwt.encode({'exp': datetime.utcnow() + timedelta(minutes=1)},
                           RCSVC_KEY,
                           algorithm='HS256')
    r = requests.get('<host>:8080/rarecyte/1.0/users/admin/users/' + user_id,
                    headers={'Authorization': 'svc ' rcsvc_jwt})
    return r

def base64_decode_to_json(b64str):
    b64padded = b64str + "==="
    return json.loads(base64.b64decode(b64_padded_header))

def get_rarecyte_keys(request):
    jwt_str = get_jwt_form_header(request)

    b64header = jwt_str.split('.')[0]
    jwt_header = base64_decode_to_json(b64header)
    b64payload = jwt_str.split('.')[1]
    jwt_payload = base64_decode_to_json(b64payload)
    public_key_url = jwt_payload['iss'] = ".well-known/jwks.json"
    r = requests.get(public_key_url)
    jwt_kid = jwt_header['kid']
    data = r.json()
    keys = data['keys']
    key_json = ""
    for key in keys:
        if key['kid'] == jwt_kid:
            key_json = key
    if key_json == "":
        return HttpResponse("Token encoded with invalid key")
    public_key = RSAAlgorithm.from_jwk(json.dumps(key_json))
    try:
        payload = jwt.decode(jwt_str,
                             public_key,
                             algorithms=['RS256'],
                             audience='https://test.glencoesoftware.com/test-jwt-api')
        if datetime.utcfromtimestamp(payload['exp']) <= datetime.utcnow():
            return HttpResponse("Token has expired")
    except jwt.InvalidSignatureError as ise:
        log.error("Invalid JWT submitted")
        return HttpResponse("Invalid JWT submitted", status=403)
    except jwt.ExpiredSignatureError as ese:
        log.error("Expired JWT submitted")
        return HttpResponse("Expired JWT submitted", status=403)

    get_user_info_from_rcsvc(payload['sub'])

    omero_manager.create_session()
    try:
        session = get_session(payload['sub'])
        url = get_url_from_session_uuid(session.uuid.val)
        return JsonResponse({'url': url, 'session': session})
    finally:
        omero_manager.close_session()

