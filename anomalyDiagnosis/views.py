from django.shortcuts import render, render_to_response
from django.http import HttpResponse, JsonResponse
from anomalyDiagnosis.models import Update, Event
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils import timezone
from django.db import transaction
from django.db.models import Q
import json
import socket
import csv
import time
from anomalyDiagnosis.thresholds import satisfied_qoe
from datetime import date, datetime, timedelta
from anomalyDiagnosis.diag_utils import *
from anomalyDiagnosis.add_user import *
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

def showUsers(request):
    users = User.objects.all()
    template = loader.get_template('anomalyDiagnosis/users.html')
    return HttpResponse(template.render({'users': users}, request))

def getUser(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        user_id = int(request_dict['id'][0])
        user = User.objects.get(id=user_id)
        template = loader.get_template('anomalyDiagnosis/user.html')
        return HttpResponse(template.render({'user':user}, request))
    else:
        return HttpResponse('Please denote user_id in url: http://locator/diag/get_user?id=user_id!')

def showSessions(request):
    sessions = Session.objects.all()
    template = loader.get_template('anomalyDiagnosis/sessions.html')
    return HttpResponse(template.render({'sessions': sessions}, request))

def getSession(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        session_id = int(request_dict['id'][0])
        session = Session.objects.get(id=session_id)
        hops = Hop.objects.filter(session=session)
        subnets = Subnetwork.objects.filter(session=session)
        template = loader.get_template('anomalyDiagnosis/session.html')
        return HttpResponse(template.render({'session': session, 'hops': hops, 'subnets':subnets}, request))
    else:
        return showSessions(request)

def showServers(request):
    servers = Server.objects.all()
    template = loader.get_template('anomalyDiagnosis/servers.html')
    return HttpResponse(template.render({'servers': servers}, request))

def getServer(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        server_id = int(request_dict['id'][0])
        server = Server.objects.get(id=server_id)
        template = loader.get_template('anomalyDiagnosis/server.html')
        return HttpResponse(template.render({'server':server}), request)
    else:
        return HttpResponse("Please denote the server_id in the url: http://locator/diag/get_server?id=server_id")

def getNetwork(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        network_id = int(request_dict['id'][0])
        network = Network.objects.get(id=network_id)
        edges = Edge.objects.filter(Q(src__in=network.nodes.all())|Q(dst__in=network.nodes.all()))
        template = loader.get_template('anomalyDiagnosis/network.html')
        return HttpResponse(template.render({'network': network, 'edges':edges}, request))
    else:
        return showNetworks(request)

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

def getDevice(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        device_id = int(request_dict['id'][0])
        device = DeviceInfo.objects.get(id=device_id)
        template = loader.get_template('anomalyDiagnosis/device.html')
        return HttpResponse(template.render({'device':device}, request))
    else:
        return HttpResponse("Please denote the device_id in the URL: http://locator/diag/get_device?id=device_id")

def showEvents(request):
    events = Event.objects.all()
    template = loader.get_template('anomalyDiagnosis/events.html')
    return HttpResponse(template.render({'events': events}, request))

def getEvents(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        user_id = int(request_dict['id'][0])
        user = User.objects.get(id=user_id)
        events = user.events.all()
        template = loader.get_template('anomalyDiagnosis/events.html')
        return HttpResponse(template.render({'user':user, 'events':events}, request))
    else:
        return HttpResponse("Please denote the user_id in url: http://locator/diag/get_events?id=user_id")

def showAnomalies(request):
    anomalies = Anomaly.objects.all()
    template = loader.get_template('anomalyDiagnosis/anomalies.html')
    return HttpResponse(template.render({'anomalies': anomalies}, request))

def getAnomalyByID(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        anomaly_id = int(request_dict['id'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        template = loader.get_template('anomalyDiagnosis/anomaly.html')
        return HttpResponse(template.render({'anomaly':anomaly}, request))
    else:
        return HttpResponse('Please denote the anomaly_id in the url: http://locator/diag/get_anomaly?id=anomaly_id')

def getAnomaliesByUser(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        user_id = int(request_dict['id'][0])
        user = User.objects.get(id=user_id)
        anomalies = user.anomalies.all()
        template = loader.get_template('anomalyDiagnosis/anomalies.html')
        return HttpResponse(template.render({'user': user, 'anomalies': anomalies}, request))
    else:
        return HttpResponse("Please denote the user_id in url: http://locator/diag/get_anomalies?id=user_id")

@csrf_exempt
def getJsonNetworkGraph(request):
    url = request.get_full_path()
    graph = {"links": [], "nodes": []}
    nodes = []
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if ('id' in request_dict.keys()):
            for session_id in request_dict['id']:
                session = Session.objects.get(id=session_id)
                client_node = Node.objects.get(ip=session.src_ip)
                server_node = Node.objects.get(ip=session.dst_ip)

                if "client_" + str(client_node.id) not in nodes:
                    nodes.append("client_" + str(client_node.id))
                    graph["nodes"].append({"name": client_node.name, "type": "client", "id": client_node.id})

                preID = nodes.index("client_" + str(client_node.id))

                if "server_" + str(server_node.id) not in nodes:
                    nodes.append("server_" + str(server_node.id))
                    graph["nodes"].append({"name": server_node.name, "type": "server", "id": server_node.id})

                lastID = nodes.index("server_" + str(server_node.id))

                for net in session.route_networks.all():
                    if "network_" + str(net.id) not in nodes:
                        nodes.append("network_" + str(net.id))
                        graph["nodes"].append({"name": net.name, "type": "network", "id": net.id})
                    curID = nodes.index("network_" + str(net.id))
                    if preID <= curID:
                        curEdge = {"source": preID, "target": curID}
                    else:
                        curEdge = {"source": curID, "target": preID}
                    if curEdge not in graph["links"]:
                        graph["links"].append(curEdge)
                    preID = curID

                if preID <= lastID:
                    lastEdge = {"source": preID, "target": lastID}
                else:
                    lastEdge = {"source": lastID, "target": preID}

                if lastEdge not in graph["links"]:
                    graph["links"].append(lastEdge)

            return JsonResponse(graph)
        else:
            return HttpResponse("No session is selected!")
    else:
        return HttpResponse(
            "Please select the checkboxes in the url: http://manage.cmu-agens.com/verify/show_sessions")

def getNetworkGraph(request):
    url = request.get_full_path()
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        ids = request_dict['id']
        template = loader.get_template("anomalyDiagnosis/netGraph.html")
        return HttpResponse(template.render({'ids': ids}, request))
    else:
        sessions = Session.objects.all()
        ids = []
        for session in sessions:
            ids.append(session.id)
        template = loader.get_template("anomalyDiagnosis/netGraph.html")
        return HttpResponse(template.render({'ids': ids}, request))

# Add the hops in the Client's route and get the client's route networks, server, and device info.
@csrf_exempt
@transaction.atomic
def addRoute(request):
    if request.method == "POST":
        ## Update the client info
        # print(request.body)
        start_time = time.time()
        client_info = json.loads(request.body.decode("utf-8"))
        add_user(client_info)
        time_elapsed = time.time() - start_time
        print("The total time to process an add route request is : " + str(time_elapsed) + " seconds!")
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
        try:
            session = Session.objects.get(client_ip=client, server_ip=server)
            update = Update(session_id=session.id, qoe=qoe, satisfied=(qoe >= satisfied_qoe))
            update.save()
            isUpdated = update_attributes(client, server, update)
        except:
            return HttpResponse("No")
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
        diagRst = diagnose(client_ip, server_ip, qoe, anomalyType)
    return JsonResponse(diagRst)