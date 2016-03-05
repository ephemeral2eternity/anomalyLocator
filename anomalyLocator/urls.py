from django.conf.urls import patterns, url
from anomalyLocator import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^nodes$', views.showNodes, name='showNodes'),
	url(r'^add$', views.addRoute, name='addRoute'),
	url(r'^exist$', views.checkRoute, name='checkRoute'),
]
