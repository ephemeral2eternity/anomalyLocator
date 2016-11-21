from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from anomalyDiagnosis.models import Node, Client, Network, Server, DeviceInfo, Hop, Edge
from anomalyDiagnosis.models import Update, Event, Cause, Diagnosis
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils import timezone
from django.db import transaction
import json
import socket
import csv
import time
from datetime import date, datetime, timedelta
from anomalyDiagnosis.diag_utils import *
import urllib

# Show detailed info of all clients connecting to this agent.
def index(request):
    hostname = socket.gethostname()
    ip = get_exp_ip()
    template = loader.get_template('anomalyDiagnosis/index.html')
    return HttpResponse(template.render({'name': hostname, 'ip': ip}, request))

def showNetworks(request):
    networks = Network.objects.all()
    template = loader.get_template('anomalyDiagnosis/networks.html')
    return HttpResponse(template.render({'networks': networks}, request))

def showClients(request):
    clients = Client.objects.all()
    template = loader.get_template('anomalyDiagnosis/clients.html')
    return HttpResponse(template.render({'clients': clients}, request))

def showServers(request):
    servers = Server.objects.all()
    template = loader.get_template('anomalyDiagnosis/servers.html')
    return HttpResponse(template.render({'servers': servers}, request))

def getNetwork(request):
    # network_dict = {}
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        network_id = int(request_dict['id'][0])
        network = Network.objects.get(id=network_id)
        # network_dict['type'] = network.type
        # network_dict['name'] = network.name
        # network_dict['as'] = network.ASNumber
        # network_dict['latitude'] = network.latitude
        # network_dict['longitude'] = network.longitude
        # network_dict['city'] = network.city
        # network_dict['region'] = network.region
        # network_dict['country'] = network.country
        # network_dict['latest_update'] = str(network.updates.latest('timestamp'))

    template = loader.get_template('anomalyDiagnosis/network.html')
    return HttpResponse(template.render({'network': network}, request))

@csrf_exempt
def editNetwork(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        network_id = int(request_dict['id'][0])
        network = Network.objects.get(id=network_id)
        if request.method == "POST":
            network_info = request.POST.dict()
            print(network_info)
            network.isp = network_info['isp']
            network.ASNumber = int(network_info['asn'])
            network.city = network_info['city']
            network.region = network_info['region']
            network.country = network_info['country']
            network.save()
            template = loader.get_template('anomalyDiagnosis/network.html')
            return HttpResponse(template.render({'network':network}, request))
        else:
            template = loader.get_template('anomalyDiagnosis/edit_network.html')
            return HttpResponse(template.render({'network':network}, request))
    else:
        return HttpResponse("Wrong network id denoted!")


def showNodesPerNetwork(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        network_id = int(request_dict['id'][0])
        network = Network.objects.get(id=network_id)
    else:
        network = Network.objects.first()
    template = loader.get_template('anomalyDiagnosis/nodes_per_network.html')
    return HttpResponse(template.render({'network': network}, request))

def showNodes(request):
    nodes = Node.objects.all()
    template = loader.get_template('anomalyDiagnosis/nodes.html')
    return HttpResponse(template.render({'nodes':nodes}, request))

def showUpdates(request):
    updates = Update.objects.all()
    template = loader.get_template('anomalyDiagnosis/updates.html')
    return HttpResponse(template.render({'updates': updates}, request))

def showDevices(request):
    devices = DeviceInfo.objects.all()
    template = loader.get_template('anomalyDiagnosis/devices.html')
    return HttpResponse(template.render({'devices': devices}, request))

def showEvents(request):
    events = Event.objects.all()
    template = loader.get_template('anomalyDiagnosis/events.html')
    return HttpResponse(template.render({'events': events}, request))

def showAnomalies(request):
    anomalies = Anomaly.objects.all()
    template = loader.get_template('anomalyDiagnosis/anomalies.html')
    return HttpResponse(template.render({'anomalies': anomalies}, request))

def getDiagnosisResult(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        anomaly_id = int(request_dict['id'][0])
        diagRst = Diagnosis.objects.get(id=anomaly_id)
    else:
        diagRst = Network.objects.last()
    template = loader.get_template('anomalyDiagnosis/diagnosis_result.html')
    return HttpResponse(template.render({'diagRst': diagRst}, request))

def dumpAnomalies(request):
    anomalies_json = {}
    anomalies = Anomaly.objects.all()
    for anomaly in anomalies:
        diag_result = Diagnosis.objects.get(id=anomaly.id)
        anomalies_json[anomaly.id] = {"type": anomaly.type, "client": anomaly.client, "server": anomaly.server,
                                      "qoe": "{:.4f}".format(anomaly.qoe), "timestamp": anomaly.timestamp.timestamp()}
        anomalies_json[anomaly.id]["causes"] = {}
        total_anomalies = diag_result.total
        for cause in diag_result.causes.all():
            anomalies_json[anomaly.id]["causes"][cause.descr] = "{:.4f}".format(cause.occurance / float(total_anomalies))

    output_filename = "anomalies.json"
    response = HttpResponse(content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename=' + output_filename
    json.dump(anomalies_json, response, indent=4, sort_keys=True)
    return response

def deleteAnomalies(request):
    Diagnosis.objects.all().delete()
    Anomaly.objects.all().delete()
    return showAnomalies(request)

# Add the hops in the Client's route and get the client's route networks, server, and device info.
@csrf_exempt
@transaction.atomic
def addRoute(request):
    if request.method == "POST":
        ## Update the client info
        # print(request.body)
        # start_time = time.time()
        client_info = json.loads(request.body.decode("utf-8"))
        try:
            client = Client.objects.get(ip=client_info['ip'])
            client.name = client_info['name']
        except:
            client = Client(name=client_info['name'], ip=client_info['ip'])
        # print("Client %s route length %d " % (client_obj.name, client_obj.route.count()))

        ## Update the client network
        try:
            client_network = Network.objects.get(type="access", ASNumber=client_info['AS'],
                                 latitude=client_info['latitude'], longitude=client_info['longitude'])
            client_network.name = client_info['ISP']
            client_network.city = client_info['city']

        except:
            client_network = Network(type="access", name=client_info['ISP'], ASNumber=client_info['AS'],
                                 latitude=client_info['latitude'], longitude=client_info['longitude'],
                                 city = client_info['city'], region = client_info['region'], country = client_info['country'])
            client_network.save()

        ## Update Client Node object
        try:
            client_node = Node.objects.get(ip = client_info['ip'], type="client")
            client_node.name = client_info['name']
            client_node.network_id = client_network.id
        except:
            client_node = Node(ip=client_info['ip'], name=client_info['name'], type="client", network_id=client_network.id)
        client_node.save()
        if client_node not in client_network.nodes.all():
            client_network.nodes.add(client_node)
        client.network_id = client_network.id

        # time_elapsed = time.time() - start_time
        # print("1.1 The total time to process an add route request is : " + str(time_elapsed) + " seconds!")

        ## Update the client device attribute
        device_info = client_info['device']
        try:
            device = DeviceInfo.objects.get(device=device_info['device'], os=device_info['os'],
                                            player=device_info['player'], browser=device_info['browser'])
        except:
            device = DeviceInfo(device=device_info['device'], os=device_info['os'],
                                player=device_info['player'], browser=device_info['browser'])
        device.save()
        client.device = device

        ## Add server object
        server_info = client_info['server']
        try:
            server = Server.objects.get(ip=server_info['ip'])
            server.name = server_info['name']
        except:
            server = Server(ip=server_info['ip'], name=server_info['name'])

        # server network
        try:
            srv_network = Network.objects.get(type="cloud", ASNumber=server_info['AS'],
                                              latitude=server_info['latitude'], longitude=server_info['longitude'])
            srv_network.name = server_info['ISP']
            srv_network.city = server_info['city']
            srv_network.region = server_info['region']
            srv_network.country = server_info['country']
        except:
            srv_network = Network(type="cloud", name=server_info['ISP'], ASNumber=server_info['AS'],
                                  latitude=server_info['latitude'], longitude=server_info['longitude'],
                                  city=server_info['city'], region = server_info['region'], country = server_info['country'])
        srv_network.save()

        # Update server network id to server object
        server.network_id = srv_network.id
        server.save()
        client.server = server
        client.save()

        ## Client add route
        client.route.clear()
        client.route_networks.clear()
        hop_id = 0
        first_hop = Hop(client=client, node=client_node, hopID=hop_id)
        first_hop.save()
        client.route_networks.add(client_network)
        # print("Client %s route length %d " % (client_obj.name, client_obj.route.count()))
        # time_elapsed = time.time() - start_time
        # print("1.2 The total time to process an add route request is : " + str(time_elapsed) + " seconds!")

        ## Update all nodes' info in the route
        preNode = client_node
        for i, node in enumerate(client_info['route']):
            node_ip = node['ip']

            # Get node type
            if node_ip == server.ip:
                node_type = "server"
            else:
                node_type = "router"

            # Get network type
            if node['AS'] == client_network.ASNumber:
                net_type = "access"
            elif node['AS'] == srv_network.ASNumber:
                net_type = "cloud"
            else:
                net_type = "transit"

            try:
                node_obj = Node.objects.get(ip=node_ip)
                node_obj.name = node['name']
                node_obj.type = node_type
            except:
                node_obj = Node(name=node['name'], ip=node_ip, type=node_type)
            node_obj.save()

            try:
                node_network = Network.objects.get(type=net_type, ASNumber=node['AS'],
                                                    latitude=node['latitude'], longitude=node['longitude'])
            except:
                node_network = Network(type=net_type, ASNumber=node['AS'], name = node['ISP'],
                                       latitude=node['latitude'], longitude=node['longitude'],
                                       city = node['city'], region = node['region'], country = node['country'])
            node_network.save()

            if node_obj not in node_network.nodes.all():
                node_network.nodes.add(node_obj)
                node_network.save()

            node_obj.network_id = node_network.id
            node_obj.save()

            if (node_network.id != client_network.id) and (node_network.id != srv_network.id):
                client.route_networks.add(node_network)

            ## save current hop to a route
            hop_id += 1
            cur_hop = Hop(client=client, node=node_obj, hopID=hop_id)
            cur_hop.save()
            # print("Client %s route length %d " % (client_obj.name, client_obj.route.count()))

            ## Add Edge Object
            curNode = node_obj
            if curNode.ip < preNode.ip:
                srcNode = curNode
                dstNode = preNode
            else:
                srcNode = preNode
                dstNode = curNode

            try:
                edge_obj = Edge.objects.get(src=srcNode, dst=dstNode)
            except:
                edge_obj = Edge(src=srcNode, dst=dstNode)
            edge_obj.save()
            preNode = curNode
        # time_elapsed = time.time() - start_time
        # print("2.%d The total time to process an add route request is : %s seconds!" % (i, time_elapsed))
        client.route_networks.add(srv_network)
        client.pathLen = client.route.count()
        client.save()
        # time_elapsed = time.time() - start_time
        # print("3. The total time to process an add route request is : " + str(time_elapsed) + " seconds!")
        return HttpResponse("Add successfully!")
    else:
        return HttpResponse(
            "Please use the POST method for http://locator_ip/diag/add request to add new info for a client!")


@csrf_exempt
@transaction.atomic
def update(request):
    isUpdated = False
    ## Add updates to all attributes of the client's session
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('client' in request_dict.keys()) and ('server' in request_dict.keys()) and ('qoe' in request_dict.keys()):
        client = request_dict['client'][0]
        server = request_dict['server'][0]
        qoe = float(request_dict['qoe'][0])
        update = Update(client_ip=client, server_ip=server, qoe=qoe)
        update.save()
        isUpdated = update_attributes(client, update)
    if isUpdated:
        return HttpResponse("Yes")
    else:
        return HttpResponse("No")


@csrf_exempt
@transaction.atomic
def addEvent(request):
    ## Add updates to all attributes of the client's session
    event = {}
    isAdded = False
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('client' in request_dict.keys()) and ('typ' in request_dict.keys()) \
            and ('prev' in request_dict.keys()) and('cur' in request_dict.keys()):
        client_ip = request_dict['client'][0]
        event['type'] = request_dict['typ'][0]
        event['prevVal'] = request_dict['prev'][0]
        event['curVal'] = request_dict['cur'][0]
        isAdded = add_event(client_ip, event)

    if isAdded:
        return HttpResponse("Yes")
    else:
        return HttpResponse("No")

@csrf_exempt
@transaction.atomic
def diagnosis(request):
    ## Diagnosis result for an anomaly.
    diagRst = {}
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    start_time = time.time()
    if ('client' in request_dict.keys()) and ('server' in request_dict.keys()) \
            and ('qoe' in request_dict.keys()) and ('type' in request_dict.keys()):
        client_ip = request_dict['client'][0]
        server_ip = request_dict['server'][0]
        qoe = request_dict['qoe'][0]
        anomalyType = request_dict['type'][0]
        anomaly = label_suspects(client_ip, server_ip, qoe, anomalyType)
        total, diagRst = diagnose(anomaly)

        time_to_diagnose = time.time() - start_time
        diag = Diagnosis(id=anomaly.id, total=total, timeToDiagnose=time_to_diagnose)
        diag.save()
        ## Save diagnosis result to database
        for causeDesc, occur in diagRst.items():
            cause = Cause(descr=causeDesc, occurance=occur)
            cause.save()
            diag.causes.add(cause)
            diagRst[causeDesc] = occur/total
        diag.save()
    return JsonResponse(diagRst)