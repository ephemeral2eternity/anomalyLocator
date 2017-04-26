from django.shortcuts import render, render_to_response
from django.http import HttpResponse, JsonResponse
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.db.models import Q
from datetime import date, datetime, timedelta
from anomalyDiagnosis.update_utils import *
from anomalyDiagnosis.add_user import *
from collections import defaultdict
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

# @description Show all ISPs discovered
def showISPs(request):
    isps = ISP.objects.all()
    peerings = PeeringEdge.objects.all()
    template = loader.get_template('anomalyDiagnosis/isps.html')
    return  HttpResponse(template.render({'isps':isps, 'peerings':peerings}, request))

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

# @description Show details of a given ISP denoted by its ASNumber (as=xxx)
def getISP(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('as' in request_dict.keys()):
        as_num = int(request_dict['as'][0])
        isp = ISP.objects.get(ASNumber=as_num)
        peerings = PeeringEdge.objects.filter(Q(srcISP__ASNumber=isp.ASNumber)|Q(dstISP__ASNumber=isp.ASNumber))
        peers = []
        for pEdge in peerings.all():
            if pEdge.srcISP.ASNumber == isp.ASNumber:
                peers.append(pEdge.dstISP)
            else:
                peers.append(pEdge.srcISP)
        template = loader.get_template('anomalyDiagnosis/isp.html')
        return HttpResponse(template.render({'isp': isp, 'peers': peers}, request))
    else:
        return HttpResponse("Please denote the AS # in http://cloud_agent/diag/get_isp?as=as_num!")

# @description Delete 1 isp
def deleteISP(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('as' in request_dict.keys()):
        as_num = int(request_dict['as'][0])
        isp = ISP.objects.get(ASNumber=as_num)
        isp.delete()
        return showISPs(request)
    else:
        return HttpResponse("Please denote the AS # in http://cloud_agent/diag/delete_isp?as=as_num!")

# @description Draw isps' networks in different colors on a world map
def getISPMap(request):
    url = request.get_full_path()
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        str_ids = request_dict['as']
        ids = []
        for str_id in str_ids:
            ids.append(str_id.split("#")[1])
        ids_json = json.dumps(ids)
    else:
        isps = ISP.objects.all().distinct()
        ids = []
        for isp in isps:
            ids.append(isp.ASNumber)
        ids_json = json.dumps(ids)
    template = loader.get_template("anomalyDiagnosis/map.html")
    return HttpResponse(template.render({'ids': ids_json}, request))

# @description Draw isps' peering links in a chord graph
def getISPPeering(request):
    url = request.get_full_path()
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        str_ids = request_dict['as']
        ids = []
        for str_id in str_ids:
            ids.append(str_id.split("#")[1])
        ids_json = json.dumps(ids)
    else:
        isps = ISP.objects.all().distinct()
        ids = []
        for isp in isps:
            ids.append(isp.ASNumber)
        ids_json = json.dumps(ids)
    template = loader.get_template("anomalyDiagnosis/ispPeeringGraph.html")
    return HttpResponse(template.render({'ids': ids_json}, request))

# @description Get ISPs' networks info in json file. ISPs denoted by their AS numbers.
# Prepare the data for function: getISPMap
def getISPNetJson(request):
    url = request.get_full_path()
    isp_nets = {}
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if ('as' in request_dict.keys()):
            as_nums = request_dict['as']
            for asn in as_nums:
                isp = ISP.objects.get(ASNumber=asn)
                isp_nets[isp.name] = []
                for net in isp.networks.distinct():
                    isp_nets[isp.name].append({"lat": net.latitude, "lon": net.longitude, "netsize": net.nodes.count(), "asn": "AS " + str(isp.ASNumber)})
    return JsonResponse(isp_nets, safe=False)

def getMapJson(request):
    servers = Node.objects.filter(type="server")

    srv_objs = []
    for srv in servers:
        srv_objs.append({"lat": srv.network.latitude, "lon": srv.network.longitude, "name": srv.name, "ip": srv.ip, "type":"server"})

    isps = ISP.objects.all()
    isp_nets = []
    for isp in isps:
        for net in isp.networks.distinct():
            isp_nets.append({"lat": net.latitude, "lon": net.longitude, "netsize": net.nodes.count(),
                                       "asn": "AS " + str(isp.ASNumber), "type":"isp", "name":isp.name, "netID":net.id})

    map_dict = {}
    map_dict["server"] = srv_objs
    map_dict["network"] = isp_nets

    return JsonResponse(map_dict, safe=False)

# @description Get the peering links in json file of all isps denoted by their as numbers.
# Prepare the data for function: getISPPeering
def getISPPeersJson(request):
    url = request.get_full_path()
    isp_nets = {}
    peering_json = {}
    all_isps_related = []
    draw_all = False
    as_nums = []
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if ('as' in request_dict.keys()):
            as_nums = request_dict['as']
            draw_all = False
        else:
            draw_all = True
    else:
        draw_all = True

    if draw_all:
        all_isps = ISP.objects.all()
        for cur_as in all_isps:
            all_isps_related.append(cur_as.name + "(AS " + str(cur_as.ASNumber) + ")")
        all_peering_links = PeeringEdge.objects.all().distinct()
    else:
        isps_to_draw = []
        for asn in as_nums:
            cur_as = ISP.objects.get(ASNumber=asn)
            isps_to_draw.append(asn)
            cur_isp_name = cur_as.name + "(AS " + str(cur_as.ASNumber) + ")"
            all_isps_related.append(cur_isp_name)

        all_peering_links = PeeringEdge.objects.filter(
            Q(srcISP__ASNumber__in=isps_to_draw) | Q(dstISP__ASNumber__in=isps_to_draw)).distinct()

        for link in all_peering_links:
            src_isp_name = link.srcISP.name + "(AS " + str(link.srcISP.ASNumber) + ")"
            dst_isp_name = link.dstISP.name + "(AS " + str(link.dstISP.ASNumber) + ")"

            if src_isp_name not in all_isps_related:
                all_isps_related.append(src_isp_name)

            if dst_isp_name not in all_isps_related:
                all_isps_related.append(dst_isp_name)

    all_isps_num = len(all_isps_related)
    peering_mat = [[0 for x in range(all_isps_num)] for y in range(all_isps_num)]
    for link in all_peering_links:
        src_isp_name = link.srcISP.name + "(AS " + str(link.srcISP.ASNumber) + ")"
        dst_isp_name = link.dstISP.name + "(AS " + str(link.dstISP.ASNumber) + ")"
        src_idx = all_isps_related.index(src_isp_name)
        dst_idx = all_isps_related.index(dst_isp_name)
        peering_mat[src_idx][dst_idx] = 1
        peering_mat[dst_idx][src_idx] = 1

        peering_json["packageNames"] = all_isps_related
        peering_json["matrix"] = peering_mat

    return JsonResponse(peering_json, safe=False)

def getSession(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        session_id = int(request_dict['id'][0])
        try:
            session = Session.objects.get(id=session_id)
            hops = Hop.objects.filter(session=session)
            subnets = Subnetwork.objects.filter(session=session)
            template = loader.get_template('anomalyDiagnosis/session.html')
            return HttpResponse(template.render({'session': session, 'hops': hops, 'subnets':subnets}, request))
        except:
            return HttpResponse("Session with id : " + str(session_id) + " does not exist!")
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
            try:
                org_network = Network.objects.get(ASNumber=int(network_info['asn']), latitude=network.latitude, longitude=network.longitude)
                for node in network.nodes.all():
                    if node not in org_network.nodes.all():
                        org_network.nodes.add(node)
                for session in network.related_sessions.all():
                    if session not in org_network.related_sessions.all():
                        org_network.related_sessions.add(session)
                org_network.save()
                network.delete()
                network = org_network
            except:
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

# @descr: prepare the anomalies data in time series to draw as event dots on different sessions.
def getAnomalyEventJson(request):
    anomalies = Anomaly.objects.all()
    anomaly_events = []
    id = 0
    for anomaly in anomalies:
        if anomaly.type == "persistent":
            anomaly_type = "severe"
        elif anomaly.type == "recurrent":
            anomaly_type = "medium"
        elif anomaly.type == "occasional":
            anomaly_type = "light"
        else:
            anomaly_type = anomaly.type

        anomaly_events.append({"id":id, "group":anomaly.session_id, "content": "anomaly:" + str(anomaly.id), "anomaly_type":anomaly_type, "start":anomaly.timestamp.strftime("%Y-%m-%d %H:%M:%S")})
        id += 1

    return JsonResponse({"anomalies":anomaly_events})

# @descr: get anomalies
def getAnomalyTypeJson(request):
    anomalies = Anomaly.objects.all()
    anomaly_types = {"severe":0, "medium":0, "light":0}
    for anomaly in anomalies:
        if anomaly.type == "persistent":
            anomaly_type = "severe"
        elif anomaly.type == "recurrent":
            anomaly_type = "medium"
        elif anomaly.type == "occasional":
            anomaly_type = "light"
        else:
            anomaly_type = anomaly.type

        anomaly_types[anomaly_type] += 1

    return JsonResponse(anomaly_types)

def getClassifiedAnomaliesJson(request):
    anomaly_origins = classifyAnomalyOrigins()
    return JsonResponse(anomaly_origins, safe=False)

## Get the anomaly count over various transit/access/cloud ISPs/networks, servers, and devices
def getAnomalyOriginHistogramJson(request):
    anomaly_origins = classifyAnomalyOrigins()
    all_origin_stats_dict = {}
    for origin_type in anomaly_origins.keys():
        cur_anomaly_origins = anomaly_origins[origin_type]
        top_origins = sorted(cur_anomaly_origins.keys())
        origin_stats_dict = {
            "origin":top_origins,
            "light":[],
            "medium":[],
            "severe":[],
            "total":[]
        }

        for i, origin in enumerate(top_origins):
            anomaly_pts = cur_anomaly_origins[origin]
            cur_obj = {
                "light": {"y":0, "label":""},
                "medium": {"y":0, "label":""},
                "severe": {"y":0, "label":""},
                "total": {"y":0, "label":""}
            }

            for anomaly_pt in anomaly_pts:
                cur_obj[anomaly_pt["type"]]["y"] += anomaly_pt["count"]
                cur_obj["total"]["y"] += anomaly_pt["count"]
                cur_obj[anomaly_pt["type"]]["label"] += str(anomaly_pt["id"]) + ","
                cur_obj["total"]["label"] += str(anomaly_pt["id"]) + ","

            origin_stats_dict["light"].append(cur_obj["light"])
            origin_stats_dict["medium"].append(cur_obj["medium"])
            origin_stats_dict["severe"].append(cur_obj["severe"])
            origin_stats_dict["total"].append(cur_obj["total"])

        # print(origin_stats_dict)
        all_origin_stats_dict[origin_type] = origin_stats_dict

    return JsonResponse(all_origin_stats_dict, safe=False)

# @ descr: get all anomalies in json formats
def getAllAnomaliesJson(request):
    url = request.get_full_path()
    if "?" in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        last_ts = request_dict['ts'][0]
        last_dt = datetime.datetime.utcfromtimestamp(float(last_ts)).replace(tzinfo=pytz.utc)
        anomalies = Anomaly.objects.filter(timestamp__gt=last_dt)
    else:
        anomalies = Anomaly.objects.all()
    locator = socket.gethostname()
    anomaly_json = []
    for anomaly in anomalies:
        anomalous_session = Session.objects.get(id=anomaly.session_id)
        cur_anomaly = {"type": anomaly.type, "timestamp": anomaly.timestamp.timestamp(), "locator": locator, "lid":anomaly.id,
                       "session_lid":anomaly.session_id, "client":anomalous_session.client.ip, "server":anomalous_session.server.ip,
                       "timeToDiagnose":anomaly.timeToDiagnose}
        top_causes = get_top_cause(anomaly)
        num_top_cause = len(top_causes)
        if num_top_cause > 0:
            origin_count = 1 / float(num_top_cause)
        origin_list = []
        for cause in top_causes:
            origin_type = cause.type
            if origin_type == "network":
                obj = Network.objects.get(id=cause.obj_id)
                origin_list.append({"type":"network", "name":obj.isp.name, "as":obj.isp.ASNumber, "latitude":obj.latitude, "longitude":obj.longitude, "lid":obj.id, "count":origin_count})
            elif origin_type == "server":
                obj = Node.objects.get(id=cause.obj_id)
                origin_list.append(
                    {"type": "server", "name": obj.name, "ip": obj.ip, "lid":obj.id, "count": origin_count})
            elif origin_type == "device":
                obj = DeviceInfo.objects.get(id=cause.obj_id)
                origin_list.append(
                    {"type": "device", "lid":obj.id, "device":obj.__str__(), "count": origin_count})
            elif origin_type == "event":
                obj = Event.objects.get(id=cause.obj_id)
                if obj.type == "ROUTE_CHANGE":
                    origin_list.append(
                        {"type": "route_change", "lid":anomalous_session.id, "prev": obj.prevVal,
                         "cur": obj.curVal, "count": origin_count})
                else:
                    user_changed = User.objects.get(id=obj.user_id)
                    if obj.type == "DEVICE_CHANGE":
                        origin_list.append(
                            {"type": "device", "user": user_changed.client.ip, "lid":user_changed.id, "prev": obj.prevVal,
                             "cur": obj.curVal, "count": origin_count})
                    else:
                        origin_list.append(
                            {"type": "server_change", "user": user_changed.client.ip, "lid":user_changed.id, "prev": obj.prevVal,
                             "cur": obj.curVal, "count": origin_count})
            else:
                obj = Path.objects.get(id=cause.obj_id)
                origin_list.append(
                    {"type": "path", "lid":anomalous_session.id, "length": obj.length, "count": origin_count})
        cur_anomaly["causes"] = origin_list
        anomaly_json.append(cur_anomaly)
    return JsonResponse(anomaly_json, safe=False)


def showAnomalyStats(request):
    anomaly_count = Anomaly.objects.all().count()
    template = loader.get_template('anomalyDiagnosis/anomalyStats.html')
    return HttpResponse(template.render({"anomaly_count":anomaly_count}, request))

def updateOriginQoEScore(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if ('id' in request_dict.keys()):
        anomaly_id = int(request_dict['id'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)

        anomaly = update_origin_qoe_score(anomaly)
        template = loader.get_template('anomalyDiagnosis/anomaly.html')
        return HttpResponse(template.render({'anomaly':anomaly}, request))
    else:
        return HttpResponse('Please denote the anomaly_id in the url: http://locator/diag/get_anomaly?id=anomaly_id')

def updateAllQoEScore(request):
    anomalies = Anomaly.objects.all()
    for anomaly in anomalies:
        anomaly = update_origin_qoe_score(anomaly)
    return HttpResponse("Update the QoE score for all causes in all anomalies!")


def getAnomalyGraphJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    graph = {"nodes": [], "links": []}
    node_status = {}
    nodes = []
    if ('id' in request_dict.keys()):
        anomaly_id = int(request_dict['id'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        anomaly_ts = anomaly.timestamp
        time_window_start = anomaly_ts - datetime.timedelta(minutes=update_graph_window)
        time_window_end = anomaly_ts + datetime.timedelta(minutes=update_graph_window)

        ## Get anomaly session's nodes, with name, id, type, qoe and group
        anomaly_session = Session.objects.get(id=anomaly.session_id)
        for node in anomaly_session.route.all():
            if node.id not in node_status.keys():
                node_status[node.id] = False
                nodes.append(node.id)
                node_dict = {"name": node.name, "type": node.type, "id": node.id}
                node_dict["qoe"] = get_ave_QoE(node, time_window_start, time_window_end)

                if node.type == "router":
                    node_network = node.network
                    node_dict["network_id"] = node.network.id
                    node_dict["label"] = node_network.__str__()
                elif node.type == "server":
                    node_dict["label"] = node.__str__()
                else:
                    node_user = User.objects.get(client=node)
                    node_dict["user_id"] = node_user.id
                    node_dict["label"] = node_user.device.__str__()

                graph["nodes"].append(node_dict)
            else:
                node_status[node.id] |= False

        ## Add peer sessions' nodes, with name, id, type, qoe, and group
        if anomaly.related_session_status:
            for session_status in anomaly.related_session_status.all():
                session_id = session_status.session_id
                peer_session = Session.objects.get(id=session_id)
                for node in peer_session.route.all():
                    if node.id not in node_status.keys():
                        node_status[node.id] = session_status.isGood
                        nodes.append(node.id)
                        node_dict = {"name": node.name, "type": node.type, "id": node.id}
                        node_dict["qoe"] = get_ave_QoE(node, time_window_start, time_window_end)

                        if node.type == "router":
                            node_network = node.network
                            node_dict["network_id"] = node.network.id
                            node_dict["label"] = node_network.__str__()
                        elif node.type == "server":
                            node_dict["label"] = node.__str__()
                        else:
                            node_user = User.objects.get(client=node)
                            node_dict["user_id"] = node_user.id
                            node_dict["label"] = node_user.device.__str__()

                        graph["nodes"].append(node_dict)
                    else:
                        node_status[node.id] |= session_status.isGood

        ## Update all nodes group info as suspect or good.
        for i, node_obj in enumerate(graph["nodes"]):
            if node_status[node_obj["id"]]:
                graph["nodes"][i]["group"] = "good"
            else:
                graph["nodes"][i]["group"] = "suspect"

        edge_objs = Edge.objects.filter(src_id__in=nodes, dst_id__in=nodes)
        for edge in edge_objs.all():
            srcID = nodes.index(edge.src.id)
            dstID = nodes.index(edge.dst.id)
            if (node_status[edge.src.id] and node_status[edge.dst.id]):
                edge_dict = {"source": srcID, "target": dstID, "group": "suspect"}
            else:
                edge_dict = {"source": srcID, "target": dstID, "group": "good"}
            graph["links"].append(edge_dict)

        return JsonResponse(graph)
    else:
        return JsonResponse({})


def getUpdatesJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    updates_dict = {'updates': []}
    updates_list = defaultdict(list)
    sessions = []
    if ('id' in request_dict.keys()) and ('type' in request_dict.keys()):
        obj_ids = request_dict['id']
        obj_type = request_dict['type'][0]
        if obj_type == "session":
            for obj_id in obj_ids:
                session = Session.objects.get(id=int(obj_id))
                sessions.append(session)
        elif obj_type == "network":
            for obj_id in obj_ids:
                network = Network.objects.get(id=int(obj_id))
                for session in network.related_sessions.all():
                    sessions.append(session)
        elif obj_type == "device":
            for obj_id in obj_ids:
                device = DeviceInfo.objects.get(id=int(obj_id))
                for user in device.users.all():
                    for session in user.sessions.all():
                        sessions.append(session)
        else:
            for obj_id in obj_ids:
                node = Node.objects.get(id=int(obj_id))
                for session in node.related_sessions.all():
                    sessions.append(session)

        for session in sessions:
            for update in session.updates.all():
                updates_list[update.timestamp].append({'x': update.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 'y': update.qoe, 'group':update.session_id})

        tses = sorted(updates_list.keys())
        for ts in tses:
            for update_obj in updates_list[ts]:
                updates_dict['updates'].append(update_obj)

        if ('anomaly' in request_dict.keys()):
            anomaly_id = int(request_dict['anomaly'][0])
            anomaly = Anomaly.objects.get(id=anomaly_id)
            anomaly_time = anomaly.timestamp
            update_start_window = anomaly_time - datetime.timedelta(minutes=5)
            update_end_window = anomaly_time + datetime.timedelta(minutes=5)
        else:
            if len(tses) > 0:
                update_end_window = tses[-1]
                update_start_window = update_end_window - datetime.timedelta(minutes=10)
            else:
                update_end_window = timezone.now()
                update_start_window = update_end_window - datetime.timedelta(minutes=10)
        updates_dict['start'] = update_start_window.strftime("%Y-%m-%d %H:%M:%S")
        updates_dict['end'] = update_end_window.strftime("%Y-%m-%d %H:%M:%S")

        #output = json.dumps(updates_dict, indent=4, sort_keys=True)
        #return HttpResponse(output, content_type="application/json")
        return JsonResponse(updates_dict)
    else:
        return JsonResponse({})

def getUpdates(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    sessions = []
    updates = []
    objs = []
    anomalyExisted = False
    if ('id' in request_dict.keys()) and ('type' in request_dict.keys()):
        obj_ids = request_dict['id']
        obj_ids_str = ",".join(obj_ids)
        obj_type = str(request_dict['type'][0])
        if obj_type == "session":
            for obj_id in obj_ids:
                session = Session.objects.get(id=int(obj_id))
                sessions.append(session)
                objs.append(session)
        elif obj_type == "network":
            for obj_id in obj_ids:
                network = Network.objects.get(id=int(obj_id))
                objs.append(network)
                for session in network.related_sessions.all():
                    sessions.append(session)
        elif obj_type == "device":
            for obj_id in obj_ids:
                device = DeviceInfo.objects.get(id=int(obj_id))
                objs.append(device)
                for user in device.users.all():
                    for session in user.sessions.all():
                        sessions.append(session)
        else:
            for obj_id in obj_ids:
                node = Node.objects.get(id=int(obj_id))
                objs.append(node)
                for session in node.related_sessions.all():
                    sessions.append(session)
    elif ('anomaly' in request_dict.keys()):
        anomaly_id = int(request_dict['anomaly'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        obj_type = "session"
        obj_ids = []
        for related_session_status in anomaly.related_session_status.all():
            session = Session.objects.get(id=related_session_status.session_id)
            sessions.append(session)
            objs.append(session)
            obj_ids.append(str(related_session_status.session_id))
        obj_ids_str = ",".join(obj_ids)
    else:
        return HttpResponse("You have to use \"type\" and \"id\" to specify an object or use \"anomaly\" to specify an anomaly to show QoE curves!")

    if 'anomaly' in request_dict.keys():
        anomalyExisted = True
        anomaly_id = int(request_dict['anomaly'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        anomaly_time = anomaly.timestamp
        update_time_window_start = anomaly_time - datetime.timedelta(minutes=5)
        update_time_window_end = anomaly_time + datetime.timedelta(minutes=5)
    else:
        session_tses = [session.latest_check for session in sessions]
        update_time_window_end = max(session_tses)
        update_time_window_start = update_time_window_end - datetime.timedelta(minutes=10)

    for session in sessions:
        session_updates = session.updates.filter(timestamp__range=(update_time_window_start, update_time_window_end))
        for update in session_updates.all():
            updates.append(update)

    if anomalyExisted:
        rendered_data = {'obj_type': obj_type, 'objs': objs, 'obj_ids': obj_ids_str, 'updates': updates, 'start': update_time_window_start, 'end':update_time_window_end, 'anomaly':anomaly.id}
    else:
        rendered_data = {'obj_type': obj_type, 'objs': objs, 'obj_ids': obj_ids_str, 'updates': updates, 'start': update_time_window_start, 'end':update_time_window_end}

    template = loader.get_template('anomalyDiagnosis/updates.html')
    return HttpResponse(template.render(rendered_data, request))

def getStatusJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    status_dict = {'status': []}
    tses = []
    sessions = []
    if ('id' in request_dict.keys()) and ('type' in request_dict.keys()):
        obj_ids = request_dict['id']
        obj_type = request_dict['type'][0]
        if obj_type == "session":
            for obj_id in obj_ids:
                session = Session.objects.get(id=int(obj_id))
                sessions.append(session)
        elif obj_type == "network":
            for obj_id in obj_ids:
                network = Network.objects.get(id=int(obj_id))
                for session in network.related_sessions.all():
                    sessions.append(session)
        elif obj_type == "device":
            for obj_id in obj_ids:
                device = DeviceInfo.objects.get(id=int(obj_id))
                for user in device.users.all():
                    for session in user.sessions.all():
                        sessions.append(session)
        else:
            for obj_id in obj_ids:
                node = Node.objects.get(id=int(obj_id))
                for session in node.related_sessions.all():
                    sessions.append(session)

        id = 1
        for session in sessions:
            for status in session.status.all():
                if status.isGood:
                    state = "Good"
                else:
                    state = "Bad"

                start_ts = status.timestamp - datetime.timedelta(minutes=node_time_window)
                tses.append(status.timestamp)

                status_dict['status'].append(
                    {'id':id, 'content':state, 'start':start_ts.strftime("%Y-%m-%d %H:%M:%S"), 'end':status.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 'group': status.session_id})
                id += 1

        if ('anomaly' in request_dict.keys()):
            anomaly_id = int(request_dict['anomaly'][0])
            anomaly = Anomaly.objects.get(id=anomaly_id)
            anomaly_time = anomaly.timestamp
            update_start_window = anomaly_time - datetime.timedelta(minutes=5)
            update_end_window = anomaly_time + datetime.timedelta(minutes=5)
        else:
            update_end_window = max(tses)
            update_start_window = update_end_window - datetime.timedelta(minutes=10)

        status_dict['start'] = update_start_window.strftime("%Y-%m-%d %H:%M:%S")
        status_dict['end'] = update_end_window.strftime("%Y-%m-%d %H:%M:%S")

        # output = json.dumps(updates_dict, indent=4, sort_keys=True)
        # return HttpResponse(output, content_type="application/json")
        return JsonResponse(status_dict)
    else:
        return JsonResponse({})

def getStatus(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    sessions = []
    status_list = []
    objs = []
    if ('id' in request_dict.keys()) and ('type' in request_dict.keys()):
        obj_ids = request_dict['id']
        obj_ids_str = ",".join(obj_ids)
        obj_type = str(request_dict['type'][0])
        if obj_type == "session":
            for obj_id in obj_ids:
                session = Session.objects.get(id=int(obj_id))
                sessions.append(session)
                objs.append(session)
        elif obj_type == "network":
            for obj_id in obj_ids:
                network = Network.objects.get(id=int(obj_id))
                objs.append(network)
                for session in network.related_sessions.all():
                    sessions.append(session)
        elif obj_type == "device":
            for obj_id in obj_ids:
                device = DeviceInfo.objects.get(id=int(obj_id))
                objs.append(device)
                for user in device.users.all():
                    for session in user.sessions.all():
                        sessions.append(session)
        else:
            for obj_id in obj_ids:
                node = Node.objects.get(id=int(obj_id))
                objs.append(node)
                for session in node.related_sessions.all():
                    sessions.append(session)
    elif ('anomaly' in request_dict.keys()):
        anomaly_id = int(request_dict['anomaly'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        obj_type = "session"
        obj_ids = []
        for session_status in anomaly.related_session_status.all():
            session = Session.objects.get(id=session_status.session_id)
            sessions.append(session)
            objs.append(session)
            obj_ids.append(str(session_status.session_id))
        obj_ids_str = ",".join(obj_ids)
    else:
        return HttpResponse(
            "You have to use \"type\" and \"id\" to specify an object or use \"anomaly\" to specify an anomaly to show QoE curves!")

    session_tses = [session.latest_check for session in sessions]

    anomalyExisted = False
    if ('anomaly' in request_dict.keys()):
        anomaly_id = int(request_dict['anomaly'][0])
        anomaly = Anomaly.objects.get(id=anomaly_id)
        anomaly_time = anomaly.timestamp
        time_window_start = anomaly_time - datetime.timedelta(minutes=5)
        time_window_end = anomaly_time + datetime.timedelta(minutes=5)
        anomalyExisted = True
    else:
        time_window_end = max(session_tses)
        time_window_start = time_window_end - datetime.timedelta(minutes=10)

    for session in sessions:
        session_status = session.status.filter(timestamp__range=(time_window_start, time_window_end))
        for status in session_status.all():
            status_list.append(status)

    if anomalyExisted:
        rendered_data = {'obj_type': obj_type, 'objs': objs, 'obj_ids': obj_ids_str, 'statuses': status_list, 'start': time_window_start, 'end':time_window_end, 'anomaly':anomaly.id}
    else:
        rendered_data = {'obj_type': obj_type, 'objs': objs, 'obj_ids': obj_ids_str, 'statuses': status_list, 'start': time_window_start, 'end':time_window_end}

    template = loader.get_template('anomalyDiagnosis/statuses.html')
    return HttpResponse(template.render(rendered_data, request))

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
                        {"name": node.name, "type": node.type, "id": node.id, "ip": node.ip, "suspect": node_status})
                else:
                    graph["nodes"].append(
                    {"name": node.name, "type": node.type, "id": node.id, "ip": node.ip})

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
    net_nodes = []
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if ('id' in request_dict.keys()):
            for session_id in request_dict['id']:
                session = Session.objects.get(id=session_id)
                client_node = Node.objects.get(ip=session.client.ip)
                user = User.objects.get(client=client_node)
                server_node = Node.objects.get(ip=session.server.ip)

                for net in session.sub_networks.all():
                    if "network_" + str(net.id) not in nodes:
                        nodes.append("network_" + str(net.id))
                        net_nodes.append(net.id)
                        graph["nodes"].append({"name": net.isp.name, "type": "network", "id": net.id})

                if "user_" + str(user.id) not in nodes:
                    nodes.append("user_" + str(user.id))
                    graph["nodes"].append({"name": user.client.name, "type": "user", "id": user.id})
                    firstID = nodes.index("user_" + str(user.id))
                    userNetID = nodes.index("network_" + str(user.client.network.id))
                    graph["links"].append({"source": firstID, "target": userNetID, "group": "intra"})

                if "server_" + str(server_node.id) not in nodes:
                    nodes.append("server_" + str(server_node.id))
                    graph["nodes"].append({"name": server_node.name, "type": "server", "id": server_node.id})
                    lastID = nodes.index("server_" + str(server_node.id))
                    srvNetID = nodes.index("network_" + str(server_node.network.id))
                    graph["links"].append({"source": srvNetID, "target": lastID, "group": "intra"})

            edges = NetEdge.objects.filter(srcNet_id__in=net_nodes, dstNet_id__in=net_nodes)
            for edge in edges.all():
                srcID = nodes.index("network_" + str(edge.srcNet.id))
                dstID = nodes.index("network_" + str(edge.dstNet.id))
                if edge.isIntra:
                    link_group = "intra"
                else:
                    link_group = "inter"
                graph["links"].append({"source": srcID, "target": dstID, "group": link_group})

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
        add_route(client_info)
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
    else:
        ## Add updates to all attributes of the client's session
        url = request.get_full_path()
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if ('client' in request_dict.keys()) and ('server' in request_dict.keys()) and ('qoe' in request_dict.keys()):
            client = request_dict['client'][0]
            server = request_dict['server'][0]
            qoe = float(request_dict['qoe'][0])
            ts = str(time.time())
            qoes = {ts:qoe}
        else:
            return HttpResponse("No")
    cur_ts = time.time()
    isUpdated = update_attributes(client, server, qoes)
    duration = time.time() - cur_ts
    print("The updates processing time is : %.2f seconds" % duration)
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