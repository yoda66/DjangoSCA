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
    sql = 'select * from joff where name = joff'
    joe = ('joff','rocks')
    os.random()
    random.random()
    sql.raw('select * from stuff where joff=joff')
    aaa = get.cleaned.data.fred()
    mark_safe(joff)
    subprocess.call()
    new_number = forms.CharField('testfield1')

    def clean_testfield1(self):
        return self.cleaned_data

    def clean(self):
        forms.Form.clean(self)
        return self.cleaned_data




