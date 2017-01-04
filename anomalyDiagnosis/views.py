from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from anomalyDiagnosis.models import Update, Event
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

def showServers(request):
    servers = Server.objects.all()
    template = loader.get_template('anomalyDiagnosis/servers.html')
    return HttpResponse(template.render({'servers': servers}, request))

def getNetwork(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        network_id = int(request_dict['id'][0])
        network = Network.objects.get(id=network_id)
        template = loader.get_template('anomalyDiagnosis/network.html')
        return HttpResponse(template.render({'network': network}, request))
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

def showEvents(request):
    events = Event.objects.all()
    template = loader.get_template('anomalyDiagnosis/events.html')
    return HttpResponse(template.render({'events': events}, request))

def showAnomalies(request):
    anomalies = Anomaly.objects.all()
    template = loader.get_template('anomalyDiagnosis/anomalies.html')
    return HttpResponse(template.render({'anomalies': anomalies}, request))

'''
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
'''

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
        update = Update(client_ip=client, server_ip=server, qoe=qoe)
        update.save()
        isUpdated = update_attributes(client, server, update)
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