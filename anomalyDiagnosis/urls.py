from django.conf.urls import url
from anomalyDiagnosis import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^add$', views.addRoute, name='addRoute'),
	url(r'^update$', views.update, name='update'),
	url(r'^addEvent$', views.addEvent, name='addEvent'),
	url(r'^diag$', views.diagnosis, name='diagnosis'),
	url(r'^get_network$', views.getNetwork, name='getNetwork'),
	url(r'^nodes_per_network', views.showNodesPerNetwork, name='showNodesPerNetwork'),
	url(r'^show_nodes', views.showNodes, name='showNodes'),
	url(r'^show_networks', views.showNetworks, name='showNetworks'),
	url(r'^show_users', views.showUsers, name='showUsers'),
	url(r'^get_user', views.getUser, name='getUser'),
	url(r'^show_sessions', views.showSessions, name='showSessions'),
	url(r'^get_session', views.getSession, name='getSession'),
	url(r'^show_servers$', views.showServers, name='showServers'),
	url(r'^get_server$', views.getServer, name='getServer'),
	url(r'^show_updates', views.showUpdates, name='showUpdates'),
	url(r'^show_devices', views.showDevices, name='showDevices'),
	url(r'^get_device', views.getDevice, name='getDevice'),
	url(r'^show_events', views.showEvents, name='showEvents'),
	url(r'^get_events', views.getEvents, name='getEvents'),
	url(r'^show_anomalies', views.showAnomalies, name='showAnomalies'),
	url(r'^get_anomalies', views.getAnomalies, name='getAnomalies'),
	url(r'^edit_network', views.editNetwork, name='editNetwork'),
]
