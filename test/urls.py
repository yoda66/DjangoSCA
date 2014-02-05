from django.conf.urls.defaults import patterns, include, url
from views import search_me
from os import system

apikey = '(?P<key>[a-zA-Z0-9]{40})'
handler404 = 'views._404'
handler500 = 'views._500'

urlpatterns = patterns('',
  url(apikey, search_me)
)


