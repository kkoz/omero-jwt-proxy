from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^get_jwt$', views.get_jwt, name='get_jwt'),
    url(r'^get_session/$', views.get_session, name='get_session'),
    url(r'^check_jwt/$', views.check_jwt, name='check_jwt'),
    url(r'^test_redirect/$', views.test_redirect, name='test_redirect'),
    url(r'^get_rarecyte_keys/$', views.get_rarecyte_keys, name='get_rarecyte_keys')
]
