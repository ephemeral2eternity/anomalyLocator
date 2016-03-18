from django.conf.urls import patterns, url
from anomalyLocator import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^nodes$', views.showNodes, name='showNodes'),
	url(r'^edges$', views.showEdges, name='showEdges'),
	url(r'^gJson/$', views.getGraphJson, name='gJson'),
	url(r'^graph/$', views.getGraph, name='graph'),
	url(r'^anomalies$', views.showAnomaly, name='showAnomaly'),
	url(r'^download_anomalies$', views.downloadAnomaly, name='downloadAnomaly'),
	url(r'^add$', views.addRoute, name='addRoute'),
	url(r'^exist$', views.checkRoute, name='checkRoute'),
	url(r'^update$', views.updateRoute, name='updateRoute'),
	url(r'^locate$', views.locate, name='locate'),
]
