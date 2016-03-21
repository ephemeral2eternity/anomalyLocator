from django.shortcuts import render, render_to_response
from django.http import HttpResponse, JsonResponse
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from anomalyLocator.models import Client, Node, Edge, Anomaly
from anomalyLocator.route_utils import *
import operator
import json
import csv
import time
import urllib
from copy import deepcopy

# Show detailed info of all clients connecting to this agent.
def index(request):
	clients = Client.objects.all()
	template = loader.get_template('anomalyLocator/index.html')
	return HttpResponse(template.render({'clients':clients}, request))

# Show detailed info of all nodes.
def showNodes(request):
	nodes = Node.objects.all()
	template = loader.get_template('anomalyLocator/nodes.html')
	return HttpResponse(template.render({'nodes':nodes}, request))

# Show detailed info of all nodes.
def showEdges(request):
	edges = Edge.objects.all()
	template = loader.get_template('anomalyLocator/edges.html')
	return HttpResponse(template.render({'edges':edges}, request))

@csrf_exempt
def getGraphJson(request):
	edges = Edge.objects.all()
	node_json = []
	edge_json = []
	node_list = []
	graph = {}
	for edge in edges:
		if edge.srcIP not in node_list:
			cur_node_ip = edge.srcIP
			node_list.append(cur_node_ip)
			# cur_node = Node.objects.get(ip=cur_node_ip)
			cur_node_exist = Node.objects.filter(ip=cur_node_ip).order_by('-latest_check')
			cur_node = cur_node_exist[0]
			if cur_node_exist.count() >= 1:
				for node_idx in range(1, cur_node_exist.count()):
					cur_node_exist[node_idx].delete()
			if "No Host" in cur_node.name:
				cur_node_json = {'name' : cur_node.ip, 'group' : cur_node.nodeType}
			else:
				cur_node_json = {'name' : cur_node.name, 'group' : cur_node.nodeType}
			node_json.append(cur_node_json)
		if edge.dstIP not in node_list:
			cur_node_ip = edge.dstIP
			node_list.append(cur_node_ip)
			cur_node_exist = Node.objects.filter(ip=cur_node_ip).order_by('-latest_check')
			cur_node = cur_node_exist[0]
			if cur_node_exist.count() >= 1:
				for node_idx in range(1, cur_node_exist.count()):
					cur_node_exist[node_idx].delete()
			if "No Host" in cur_node.name:
				cur_node_json = {'name' : cur_node.ip, 'group' : cur_node.nodeType}
			else:
				cur_node_json = {'name' : cur_node.name, 'group' : cur_node.nodeType}
			node_json.append(cur_node_json)
		cur_edge = {}
		cur_edge['source'] = node_list.index(edge.srcIP)
		cur_edge['target'] = node_list.index(edge.dstIP)
		cur_edge['value'] = 1
		edge_json.append(cur_edge)
	graph['nodes'] = node_json
	graph['links'] = edge_json
	rsp = JsonResponse(graph, safe=False)
	rsp["Access-Control-Allow-Origin"] = "*"
	return rsp

def getGraph(request):
	return render_to_response("anomalyLocator/topology.html")

# Show detailed info of anomalies.
def showAnomaly(request):
	anomalies = Anomaly.objects.order_by('-id')
	template = loader.get_template('anomalyLocator/anomalies.html')
	return HttpResponse(template.render({'anomalies':anomalies}, request))

# Download all anomalies in csv files.
def downloadAnomaly(request):
	anomalies = Anomaly.objects.all()
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename="anomalies.csv"'

	writer = csv.writer(response)
	writer.writerow(['timestamp', 'client', 'normal', 'abnormal', 'peers'])
	for anomaly in anomalies:
		writer.writerow([int(time.mktime(anomaly.timestamp.timetuple())), anomaly.client, anomaly.normal, anomaly.abnormal, anomaly.peers])
	return response

@csrf_exempt
def checkRoute(request):
	url = request.get_full_path()
	params = url.split('?')[1]
	request_dict = urllib.parse.parse_qs(params)
	print(request_dict.keys())
	client_info = {}
	if ('client' in request_dict.keys()) and ('server' in request_dict.keys()):
		client_exist = Client.objects.filter(ip=request_dict['client'][0], server=request_dict['server'][0])
		if client_exist.count() > 0:
			client_obj = client_exist[0]
			client_info = {'ip' : client_obj.ip, 'server' : client_obj.server, 'route': client_obj.route}
	return JsonResponse(client_info)


@csrf_exempt
def addRoute(request):
	if request.method == "POST":
		## Update the client info
		# print(request.POST)
		print(request.body)
		client_info = json.loads(request.body.decode("utf-8"))
		client_route = route2str(client_info['route'])
		client_exist = Client.objects.filter(ip=client_info['ip'], server=client_info['server']).order_by('-latest_update')
		if client_exist.count() > 0:
			client_obj = client_exist[0]
			client_obj.name = client_info['name']
			client_obj.ip = client_info['ip']
			client_obj.server = client_info['server']
			client_obj.city = client_info['city']
			client_obj.region = client_info['region']
			client_obj.country = client_info['country']
			client_obj.AS = client_info['AS']
			client_obj.ISP = client_info['ISP']
			client_obj.latitude = client_info['latitude']
			client_obj.longitude = client_info['longitude']
			client_obj.route = client_route
			if client_exist.count() >= 1:
				for client_idx in range(1, client_exist.count()):
					client_exist[client_idx].delete()
		else:
			client_obj = Client(name=client_info['name'], ip=client_info['ip'], server=client_info['server'], city=client_info['city'], region=client_info['region'], country=client_info['country'], AS=client_info['AS'], ISP=client_info['ISP'], latitude=client_info['latitude'], longitude=client_info['longitude'], route=client_route)
		client_obj.save()

		client_node_exist = Node.objects.filter(ip=client_info['ip'])
		if client_node_exist.count() > 0:
			client_node_obj = client_node_exist[0]
			client_node_obj.ip = client_info['ip']
			client_node_obj.name = client_info['name']
			client_node_obj.city = client_info['city']
			client_node_obj.region = client_info['region']
			client_node_obj.country = client_info['country']
			client_node_obj.AS = client_info['AS']
			client_node_obj.ISP = client_info['ISP']
			client_node_obj.latitude = client_info['latitude']
			client_node_obj.longitude = client_info['longitude']
			client_node_obj.nodeType = "client"
		else:
			client_node_obj = Node(name=client_info['name'], ip=client_info['ip'], city=client_info['city'], region=client_info['region'], country=client_info['country'], AS=client_info['AS'], ISP=client_info['ISP'], latitude=client_info['latitude'], longitude=client_info['longitude'], nodeType="client", clients=client_info['ip'])
		client_node_obj.save()

		## Update all nodes' info in the route
		preNode = {'name' : client_info['name'], 'ip' : client_info['ip']}
		for node in client_info['route']:
			node_ip = node['ip']
			node_exist = Node.objects.filter(ip=node_ip)
			if node_ip == client_info['server']:
				node_type = "server"
			else:
				node_type = "router"
			if node_exist.count() > 0:
				node_obj = node_exist[0]
				node_obj.ip = node_ip
				node_obj.name = node['name']
				node_obj.city = node['city']
				node_obj.region = node['region']
				node_obj.country = node['country']
				node_obj.AS = node['AS']
				node_obj.ISP = node['ISP']
				node_obj.latitude = node['latitude']
				node_obj.longitude = node['longitude']
				node_obj.nodeType = node_type
				node_clients = node_obj.clients.split('-')
				if client_info['ip'] not in node_clients:
					node_clients.append(client_info['ip'])
					node_clients_str = '-'.join(str(c) for c in node_clients)
					node_obj.clients = node_clients_str
			else:
				node_obj = Node(name=node['name'], ip=node['ip'], city=node['city'], region=node['region'], country=node['country'], AS=node['AS'], ISP=node['ISP'], latitude=node['latitude'], longitude=node['longitude'], nodeType=node_type, clients=client_info['ip'])
			print("Saving " + str(node))
			node_obj.save()

			## Add Edge Object
			curNode = {'name' : node_obj.name, 'ip' : node_obj.ip}
			edge = {preNode['name'] : preNode['ip'], curNode['name']:curNode['ip']}
			print(edge)
			sorted_edge = sorted(edge.items(), key=operator.itemgetter(1))
			if len(sorted_edge) < 2:
				continue
			src = sorted_edge[0][0]
			srcIP = sorted_edge[0][1]
			dst = sorted_edge[1][0]
			dstIP = sorted_edge[1][1]

			edge_exist = Edge.objects.filter(srcIP=srcIP, dstIP=dstIP)
			if edge_exist.count() > 0:
				edge_obj = edge_exist[0]
				edge_obj.src = src
				edge_obj.srcIP = srcIP
				edge_obj.dst = dst
				edge_obj.dstIP = dstIP
			else:
				edge_obj = Edge(src=src, srcIP=srcIP, dst=dst, dstIP=dstIP)
			edge_obj.save()
			print("Save edge from " + src + "("+ srcIP + ")" + " to " + dst + "("+ dstIP + ")")
			preNode = deepcopy(curNode)
		return index(request)
	else:
		return HttpResponse("Please use the POST method for http://locator_ip/anomalyLocator/addRoute request to add new routes for a client!")


@csrf_exempt
def updateRoute(request):
	isUpdated = False
	url = request.get_full_path()
	params = url.split('?')[1]
	request_dict = urllib.parse.parse_qs(params)
	print(request_dict.keys())
	client_info = {}
	if ('client' in request_dict.keys()) and ('server' in request_dict.keys()):
		client_exist = Client.objects.filter(ip=request_dict['client'][0], server=request_dict['server'][0])
		if client_exist.count() > 0:
			client_obj = client_exist[0]
			client_route = client_obj.route
			update_route(client_obj.ip, client_route)
			isUpdated = True

	if isUpdated:
		return HttpResponse("Yes")
	else:
		return HttpResponse("No")

@csrf_exempt
def locate(request):
	url = request.get_full_path()
	params = url.split('?')[1]
	request_dict = urllib.parse.parse_qs(params)
	print(request_dict.keys())
	anomaly_info = {}
	if ('client' in request_dict.keys()) and ('server' in request_dict.keys()):
		client_exist = Client.objects.filter(ip=request_dict['client'][0], server=request_dict['server'][0])
		if client_exist.count() > 0:
			client_obj = client_exist[0]
			client_ip = client_obj.ip
			client_route = client_obj.route
			print("Locate anomalies in client route: " + client_route)
			anomaly_info = locate_anomaly(client_ip, client_route)
			## Add the anomaly to database
			normal_nodes_str = '-'.join(str(n) for n in anomaly_info['normal'])
			abnormal_nodes_str = '-'.join(str(n) for n in anomaly_info['abnormal'])
			peers_str = '-'.join(str(n) for n in anomaly_info['peers'])
			new_anomaly = Anomaly(client=client_ip, normal=normal_nodes_str, abnormal=abnormal_nodes_str, peers=peers_str)
			new_anomaly.save()
	return JsonResponse(anomaly_info)
