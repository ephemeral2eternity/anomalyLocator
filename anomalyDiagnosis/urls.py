from django.conf.urls import patterns, url
from anomalyDiagnosis import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^add$', views.addRoute, name='addRoute'),
	url(r'^update$', views.update, name='update'),
	url(r'^addEvent$', views.addEvent, name='addEvent'),
	url(r'^diag$', views.diagnosis, name='diagnosis'),
	url(r'^servers$', views.showServers, name='showServers'),
	url(r'^network$', views.getNetwork, name='getNetwork'),
	url(r'^show_nodes', views.showNodes, name='showNodes'),
	url(r'^show_clients', views.showClients, name='showClients'),
	url(r'^nodes_per_network', views.showNodesPerNetwork, name='showNodesPerNetwork'),
	url(r'^show_updates', views.showUpdates, name='showUpdates'),
	url(r'^show_devices', views.showDevices, name='showDevices'),
	url(r'^show_events', views.showEvents, name='showEvents'),
	url(r'^show_anomalies', views.showAnomalies, name='showAnomalies'),
	url(r'^show_diag_result', views.showDiagnosisResult, name='showDiagnosisResult'),
]
