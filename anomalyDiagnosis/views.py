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
import pytz
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
    servers = Node.objects.filter(type="server")
    template = loader.get_template('anomalyDiagnosis/servers.html')
    return HttpResponse(template.render({'servers': servers}, request))

def getServer(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        server_id = int(request_dict['id'][0])
        server = Node.objects.get(id=server_id)
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

def getNetworkJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        network_id = int(request_dict['id'][0])
        network = Network.objects.get(id=network_id)
        edges = Edge.objects.filter(Q(src__in=network.nodes.all())|Q(dst__in=network.nodes.all()))

        all_nodes = []
        node_list = []
        for node in network.nodes.all():
            all_nodes.append(node.ip)
            node_list.append({"name":node.name, "network_id":node.network_id, "ip":node.ip, "type": "in", "id":node.id})

        edge_list = []
        for edge in edges.all():
            if edge.src not in network.nodes.all():
                if edge.src.ip not in all_nodes:
                    all_nodes.append(edge.src.ip)
                    node_list.append({"name": edge.src.name, "network_id": edge.src.network_id, "ip": edge.src.ip, "type": "out", "id": edge.src.id})
            src_id = all_nodes.index(edge.src.ip)

            if edge.dst not in network.nodes.all():
                if edge.dst.ip not in all_nodes:
                    all_nodes.append(edge.dst.ip)
                    node_list.append({"name": edge.dst.name, "network_id": edge.dst.network_id, "ip": edge.dst.ip, "type": "out", "id": edge.dst.id})
            dst_id = all_nodes.index(edge.dst.ip)

            edge_list.append({"source":src_id, "target":dst_id})

        graph = {}
        graph["nodes"] = node_list
        graph["edges"] = edge_list

        #output = json.dumps(graph, indent=4, sort_keys=True)
        #return HttpResponse(output, content_type="application/json")
        return JsonResponse(graph)
    else:
        return JsonResponse({})

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
            # print(network_info)
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

def getNode(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        node_id = int(request_dict['id'][0])
        node = Node.objects.get(id=node_id)
        template = loader.get_template('anomalyDiagnosis/node.html')
        return HttpResponse(template.render({'node': node}, request))
    else:
        return HttpResponse("Please denote the node id in : http://locator/diag/get_node?id=node_id")


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

def getEventsByUser(request):
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

def getEventByID(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        event_id = int(request_dict['id'][0])
        event = Event.objects.get(id=event_id)
        template = loader.get_template('anomalyDiagnosis/event.html')
        return HttpResponse(template.render({'event': event}, request))
    else:
        return HttpResponse("Please denote the event_id in url: http://locator/diag/get_event?id=event_id")

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


def getAnomalyGraphJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    graph = {"nodes": [], "links": []}
    suspect_node_ids = []
    anomaly_session_nodes = []
    nodes = []
    if ('id' in request_dict.keys()):
        anomaly_id = int(request_dict['id'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        anomaly_ts = anomaly.timestamp
        time_window_start = anomaly_ts - datetime.timedelta(minutes=update_graph_window)
        time_window_end = anomaly_ts + datetime.timedelta(minutes=update_graph_window)

        ## Get all suspect node ids
        for cause in anomaly.causes.all():
            if cause.node:
                suspect_node_ids.append(cause.node.id)

        ## Get anomaly session's nodes, with name, id, type, qoe and group
        anomaly_session = Session.objects.get(id=anomaly.session_id)
        for node in anomaly_session.route.all():
            if node.id not in nodes:
                nodes.append(node.id)
                anomaly_session_nodes.append(node.id)
                node_dict = {"name": node.name, "type": node.type, "id": node.id}
                node_dict["qoe"] = get_ave_QoE(node.updates, time_window_start, time_window_end)
                if (node.id in suspect_node_ids):
                    if len(suspect_node_ids) == 1:
                        node_dict["group"] = "bad"
                    else:
                        node_dict["group"] = "suspect"

                    if node.type == "router":
                        node_network = Network.objects.get(id=node.network_id)
                        node_dict["network_id"] = node.network_id
                        node_dict["label"] = node_network.__str__()
                    elif node.type == "server":
                        node_dict["label"] = node.__str__()
                    else:
                        node_user = User.objects.get(client=node)
                        node_dict["user_id"] = node_user.id
                        node_dict["label"] = node_user.device.__str__()
                else:
                    node_dict["group"] = "good"
                graph["nodes"].append(node_dict)

        ## Get related sessions' nodes, with name, id, type, qoe, and group
        if anomaly.related_sessions.__contains__(','):
            related_session_ids = anomaly.related_sessions.split(',')
            for related_session_id in related_session_ids:
                peer_session = Session.objects.get(id=related_session_id)
                for node in peer_session.route.all():
                    if node.id not in nodes:
                        nodes.append(node.id)
                        node_dict = {"name": node.name, "type": node.type, "id": node.id}
                        node_dict["qoe"] = get_ave_QoE(node.updates, time_window_start, time_window_end)
                        if (node.id in suspect_node_ids):
                            if len(suspect_node_ids) == 1:
                                node_dict["group"] = "bad"
                            else:
                                node_dict["group"] = "suspect"
                        else:
                            node_dict["group"] = "good"
                        graph["nodes"].append(node_dict)

        edge_objs = Edge.objects.filter(src_id__in=nodes, dst_id__in=nodes)
        for edge in edge_objs.all():
            srcID = nodes.index(edge.src.id)
            dstID = nodes.index(edge.dst.id)
            if (edge.src.id in anomaly_session_nodes) and (edge.dst.id in anomaly_session_nodes):
                edge_dict = {"source": srcID, "target": dstID, "group": "anomalySession"}
            else:
                edge_dict = {"source": srcID, "target": dstID, "group": "relatedSession"}
            graph["links"].append(edge_dict)

        # output = json.dumps(graph, indent=4, sort_keys=True)
        # return HttpResponse(output, content_type="application/json")
        return JsonResponse(graph)
    else:
        return JsonResponse({})


def getUpdatesJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    updates_dict = {}
    if ('id' in request_dict.keys()) and ('type' in request_dict.keys()):
        obj_id = int(request_dict['id'][0])
        obj_type = request_dict['type'][0]
        if obj_type == "session":
            session = Session.objects.get(id=obj_id)
            updates = session.updates
        elif obj_type == "network":
            network = Network.objects.get(id=obj_id)
            updates = network.updates
        elif obj_type == "device":
            device = DeviceInfo.objects.get(id=obj_id)
            updates = device.updates
        else:
            node = Node.objects.get(id=obj_id)
            updates = node.updates

        updates_list = []
        for update in updates.all():
            updates_list.append({'x': update.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 'y': update.qoe, 'group':update.session_id})
        updates_dict['updates'] = updates_list

        if ('anomaly' in request_dict.keys()):
            anomaly_id = int(request_dict['anomaly'][0])
            anomaly = Anomaly.objects.get(id=anomaly_id)
            anomaly_time = anomaly.timestamp
            update_start_window = anomaly_time - datetime.timedelta(minutes=5)
            update_end_window = anomaly_time + datetime.timedelta(minutes=5)
        else:
            update_end_window = updates.last().timestamp
            update_start_window = update_end_window - datetime.timedelta(minutes=10)
        updates_dict['start'] = update_start_window.strftime("%Y-%m-%d %H:%M:%S")
        updates_dict['end'] = update_end_window.strftime("%Y-%m-%d %H:%M:%S")

        #output = json.dumps(updates_dict, indent=4, sort_keys=True)
        #return HttpResponse(output, content_type="application/json")
        return JsonResponse(updates_dict)
    else:
        return JsonResponse({})

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
def getRouterGraphJson(request):
    url = request.get_full_path()
    graph = {"links": [], "nodes": []}
    nodes = []
    isAnomaly = False
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if ('id' in request_dict.keys()):
            session_ids = request_dict['id']
        else:
            session_ids = [session.id for session in Session.objects.all()]

        if ('anoID' in request_dict.keys()):
            isAnomaly = True
            anomaly_id = int(request_dict['anoID'][0])
            anomaly = Anomaly.objects.get(id=anomaly_id)
            anomaly_ts = anomaly.timestamp
            anomaly_time_window_start = anomaly_ts - datetime.timedelta(minutes=node_time_window)

    else:
        session_ids = [session.id for session in Session.objects.all()]

    for session_id in session_ids:
        session = Session.objects.get(id=session_id)

        for node in session.route.all():
            if node.id not in nodes:
                nodes.append(node.id)

                if isAnomaly:
                    node_updates = node.updates.filter(timestamp__range=(anomaly_time_window_start, anomaly_ts))
                    node_status, _ = check_status(node_updates, session_id)
                    graph["nodes"].append(
                        {"name": node.name, "type": node.type, "id": node.id, "qs": node.node_qoe_score, "ip": node.ip, "suspect": node_status})
                else:
                    graph["nodes"].append(
                    {"name": node.name, "type": node.type, "id": node.id, "qs": node.node_qoe_score, "ip": node.ip})

    edges = Edge.objects.filter(src_id__in=nodes, dst_id__in=nodes)
    for edge in edges.all():
        srcID = nodes.index(edge.src.id)
        dstID = nodes.index(edge.dst.id)
        if edge.isIntra:
            link_group = "intra"
        else:
            link_group = "inter"
        graph["links"].append({"source": srcID, "target": dstID, "group": link_group})

    #output = json.dumps(graph, indent=4, sort_keys=True)
    #return HttpResponse(output, content_type="application/json")
    return JsonResponse(graph)

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
                client_node = Node.objects.get(ip=session.client_ip)
                user = User.objects.get(client=client_node)
                server_node = Node.objects.get(ip=session.server_ip)

                if "user_" + str(user.id) not in nodes:
                    nodes.append("user_" + str(user.id))
                    graph["nodes"].append({"name": user.client.name, "type": "user", "id": user.id, "qs": user.device.device_qoe_score})

                preID = nodes.index("user_" + str(user.id))

                if "server_" + str(server_node.id) not in nodes:
                    nodes.append("server_" + str(server_node.id))
                    graph["nodes"].append({"name": server_node.name, "type": "server", "id": server_node.id, "qs": server_node.node_qoe_score})

                lastID = nodes.index("server_" + str(server_node.id))

                for net in session.sub_networks.all():
                    if "network_" + str(net.id) not in nodes:
                        nodes.append("network_" + str(net.id))
                        graph["nodes"].append({"name": net.name, "type": "network", "id": net.id, "qs": net.network_qoe_score})
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

            #output = json.dumps(graph, indent=4, sort_keys=True)
            # return HttpResponse(output, content_type="application/json")
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
        ids_json = json.dumps(ids)
        template = loader.get_template("anomalyDiagnosis/netGraph.html")
        return HttpResponse(template.render({'ids': ids_json}, request))
    else:
        sessions = Session.objects.all()
        ids = []
        for session in sessions:
            ids.append(session.id)
        ids_json = json.dumps(ids)
        template = loader.get_template("anomalyDiagnosis/netGraph.html")
        return HttpResponse(template.render({'ids': ids_json}, request))

def getRouterGraph(request):
    url = request.get_full_path()
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        ids = request_dict['id']
        ids_json = json.dumps(ids)
        template = loader.get_template("anomalyDiagnosis/routerGraph.html")
        return HttpResponse(template.render({'ids': ids_json}, request))
    else:
        sessions = Session.objects.all()
        ids = []
        for session in sessions:
            ids.append(session.id)
        ids_json = json.dumps(ids)
        template = loader.get_template("anomalyDiagnosis/routerGraph.html")
        return HttpResponse(template.render({'ids': ids_json}, request))


def getPath(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        path_id = int(request_dict['id'][0])
        path = Path.objects.get(id=path_id)
        template = loader.get_template('anomalyDiagnosis/path.html')
        return HttpResponse(template.render({'path': path}, request))
    else:
        return HttpResponse("Please denote the path_id in url: http://locator/diag/get_path?id=path_id")

# Add the hops in the Client's route and get the client's route networks, server, and device info.
@csrf_exempt
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
def update(request):
    updates = []
    if request.method == "POST":
        qoe_info = json.loads(request.body.decode("utf-8"))
        client = qoe_info['client']
        server = qoe_info['server']
        qoes = qoe_info['qoes']
        try:
            session = Session.objects.get(client_ip=client, server_ip=server)
            for ts,qoe in qoes.items():
                dtfield = datetime.datetime.utcfromtimestamp(float(ts))
                update = Update(session_id = session.id, qoe=qoe, satisfied=(qoe >= satisfied_qoe), timestamp=dtfield)
                update.save()
                updates.append(update)
        except:
            return HttpResponse("Error: No existing session from client " + client + " to server " + server)
    else:
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
                dtfield = timezone.now()
                update = Update(session_id=session.id, qoe=qoe, satisfied=(qoe >= satisfied_qoe), timestamp=dtfield)
                update.save()
                updates.append(update)
            except:
                return HttpResponse("Error: No existing session from client " + client + " to server " + server)
        else:
            return HttpResponse("No")
    # cur_ts = time.time()
    isUpdated = update_attributes(client, server, updates)
    # duration = time.time() - cur_ts
    # print("The updates processing time is : %.2f seconds" % duration)
    if isUpdated:
        return HttpResponse("Yes")
    else:
        return HttpResponse("No")

@csrf_exempt
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
def diagnosis(request):
    ## Diagnosis result for an anomaly.
    diagRst = {}
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('client' in request_dict.keys()) and ('server' in request_dict.keys()) \
            and ('qoe' in request_dict.keys()) and ('type' in request_dict.keys()):
        client_ip = request_dict['client'][0]
        server_ip = request_dict['server'][0]
        qoe = request_dict['qoe'][0]
        anomalyType = request_dict['type'][0]
        diagRst = diagnose(client_ip, server_ip, qoe, anomalyType)
    # output = json.dumps(diagRst, indent=4, sort_keys=True)
    # return HttpResponse(output, content_type="application/json")
    return JsonResponse(diagRst)