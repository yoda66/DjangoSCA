from django import forms
from django.conf import settings
from django.contrib.humanize.templatetags import humanize
from django.core import urlresolvers
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe

import datetime
import csv
import re
import ipaddr
import logging
import urlparse

class AccountForm(webapps_forms.BaseForm):
    sql = 'select * from testdb where name = fred'
    random.random()
    sql.raw = 'select * from testdb where name = fred'
    sql.raw = 'update testdb set name = john'
    sql.raw = "insert into testdb values ('a','b','c')"
    mark_safe(aaaa)
    subprocess.call()

    def clean_testfield1(self):
        return self.cleaned_data

    def clean(self):
        forms.Form.clean(self)
        return self.cleaned_data




