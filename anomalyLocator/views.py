from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from anomalyLocator.models import Client, Node
from anomalyLocator.route_utils import *
import json
import urllib

# Create your views here.
def index(request):
	clients = Client.objects.all()
	template = loader.get_template('anomalyLocator/index.html')
	return HttpResponse(template.render({'clients':clients}, request))

# Create your views here.
def showNodes(request):
	nodes = Node.objects.all()
	template = loader.get_template('anomalyLocator/nodes.html')
	return HttpResponse(template.render({'nodes':nodes}, request))

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
		client_exist = Client.objects.filter(ip=client_info['ip'], server=client_info['server'])
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
		else:
			client_obj = Client(name=client_info['name'], ip=client_info['ip'], server=client_info['server'], city=client_info['city'], region=client_info['region'], country=client_info['country'], AS=client_info['AS'], ISP=client_info['ISP'], latitude=client_info['latitude'], longitude=client_info['longitude'], route=client_route)
		client_obj.save()

		## Update all nodes' info in the route
		for node in client_info['route']:
			node_ip = node['ip']
			node_exist = Node.objects.filter(ip=node_ip)
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
			else:
				node_obj = Node(name=node['name'], ip=node['ip'], city=node['city'], region=node['region'], country=node['country'], AS=node['AS'], ISP=node['ISP'], latitude=node['latitude'], longitude=node['longitude'])

			node_obj.save()
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
			isUpdated = update_route(client_route)

	if isUpdated:
		return HttpResponse("Yes")
	else:
		return HttpResponse("No")
