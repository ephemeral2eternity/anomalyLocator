from django.conf.urls import url
from anomalyDiagnosis import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^add$', views.addRoute, name='addRoute'),
	url(r'^update$', views.update, name='update'),
	url(r'^addEvent$', views.addEvent, name='addEvent'),
	url(r'^diag$', views.diagnosis, name='diagnosis'),
	url(r'^get_network$', views.getNetwork, name='getNetwork'),
	url(r'^get_network_json$', views.getNetworkJson, name='getNetworkJson'),
	url(r'^nodes_per_network', views.showNodesPerNetwork, name='showNodesPerNetwork'),
	url(r'^show_nodes', views.showNodes, name='showNodes'),
	url(r'^get_node', views.getNode, name='getNode'),
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
	url(r'^get_events_by_user', views.getEventsByUser, name='getEventsByUser'),
	url(r'^get_event', views.getEventByID, name='getEventByID'),
	url(r'^get_path', views.getPath, name='getPath'),
	url(r'^show_anomalies', views.showAnomalies, name='showAnomalies'),
	url(r'^get_anomalies_by_user', views.getAnomaliesByUser, name='getAnomaliesByUser'),
	url(r'^get_anomaly', views.getAnomalyByID, name='getAnomalyByID'),
	url(r'^edit_network', views.editNetwork, name='editNetwork'),
	url(r'^get_net_graph_json', views.getJsonNetworkGraph, name='getJsonNetworkGraph'),
	url(r'^get_net_graph', views.getNetworkGraph, name='getNetworkGraph'),
	url(r'^get_updates_json', views.getUpdatesJson, name='get_updates_json'),
	url(r'^get_ano_graph_json', views.getAnomalyGraphJson, name='getAnomalyGraphJson'),
	url(r'^get_router_graph_json', views.getRouterGraphJson, name='getRouterGraphJson'),
]
