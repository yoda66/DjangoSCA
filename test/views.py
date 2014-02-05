
from django.http import HttpResponse, HttpResponseForbidden
from django.db import connection
from django.template.loader import get_template
from django.template import Context

from datetime import datetime
from subprocess import Popen, PIPE
from decimal import Decimal

import json
import sys
import socket
import struct


def _apikey(key):
  cursor = connection.cursor()
  sql = 'SELECT KEY FROM apikey WHERE KEY = %s'
  try:
    cursor.execute(sql, [key])
  except:
    return False
  result = cursor.fetchone()
  if result and result[0] == key:
    return True
  return False


def _404(req):
  return _error(req,status=404,msg='invalid search url',devmsg='the search url provided did not match any regular expression to call a database search function')


def _500(req):
  return _error(req,status=500,msg='internal server error',devmsg='')


def search_me(request,key,sstr):
  if not _apikey(key):
    return _error(request,status=403,msg='invalid API key used',devmsg='the API key presented is not able to be found in our database')
  mystr = "hello world"
  return HttpResponse(mystr,status=200,content_type='application/json')


