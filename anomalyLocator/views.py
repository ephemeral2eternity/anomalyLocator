from django.shortcuts import render, render_to_response
from django.http import HttpResponse, JsonResponse
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils import timezone
from django.db import transaction
from anomalyLocator.models import Client, Node, Hop, Edge, Anomaly
from anomalyLocator.route_utils import *
import operator
import json
import csv
import time
from datetime import date, datetime, timedelta
import urllib
from copy import deepcopy


# Show detailed info of all clients connecting to this agent.
def index(request):
    clients = Client.objects.all()
    template = loader.get_template('anomalyLocator/index.html')
    return HttpResponse(template.render({'clients': clients}, request))


# Show detailed info of all nodes.
def showNodes(request):
    nodes = Node.objects.all()
    template = loader.get_template('anomalyLocator/nodes.html')
    return HttpResponse(template.render({'nodes': nodes}, request))


# Show detailed info of all nodes.
def showEdges(request):
    edges = Edge.objects.all()
    template = loader.get_template('anomalyLocator/edges.html')
    return HttpResponse(template.render({'edges': edges}, request))


# Show detailed info of all nodes.
def showUpdates(request):
    updates = Update.objects.all().order_by('-id')
    template = loader.get_template('anomalyLocator/updates.html')
    return HttpResponse(template.render({'updates': updates}, request))


# Download all updates in csv files.
def downloadUpdates(request):
    updates = Update.objects.all()
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="updates.csv"'

    writer = csv.writer(response)
    writer.writerow(['timestamp', 'client', 'server', 'qoe', 'state'])
    for update in updates:
        writer.writerow(
            [int(time.mktime(update.timestamp.timetuple())), update.client, update.server, update.qoe, update.state])
    return response


def drawAnomalies(request):
    return render_to_response("anomalyLocator/anomalyIndex.html")


@csrf_exempt
def getGraphJson(request):
    edges = Edge.objects.all()
    node_json = []
    edge_json = []
    node_list = []
    graph = {}
    for edge in edges:
        cur_node = edge.src
        if cur_node.ip not in node_list:
            node_list.append(cur_node.ip)
            if "No Host" in cur_node.name:
                cur_node_json = {'name': cur_node.ip, 'group': cur_node.nodeType}
            else:
                cur_node_json = {'name': cur_node.name, 'group': cur_node.nodeType}
            node_json.append(cur_node_json)
        cur_node = edge.dst
        if cur_node.ip not in node_list:
            node_list.append(cur_node.ip)
            if "No Host" in cur_node.name:
                cur_node_json = {'name': cur_node.ip, 'group': cur_node.nodeType}
            else:
                cur_node_json = {'name': cur_node.name, 'group': cur_node.nodeType}
            node_json.append(cur_node_json)
        cur_edge = {}
        cur_edge['source'] = node_list.index(edge.src.ip)
        cur_edge['target'] = node_list.index(edge.dst.ip)
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
    return HttpResponse(template.render({'anomalies': anomalies}, request))


def statGraph(request):
    return render_to_response("anomalyLocator/stat.html")


@csrf_exempt
def anomalyStatJson(request):
    url = request.get_full_path()
    hasPeer = 0
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if "days" in request_dict.keys():
            num_days = int(request_dict["days"][0])
            end_time = timezone.now()
            start_time = end_time - timedelta(days=num_days)
            # print(start_time)
            anomalies = Anomaly.objects.filter(timestamp__range=[start_time, end_time])
        elif "hours" in request_dict.keys():
            num_hours = int(request_dict["hours"][0])
            end_time = timezone.now()
            start_time = end_time - timedelta(hours=num_hours)
            anomalies = Anomaly.objects.filter(timestamp__range=[start_time, end_time])
        elif ("start" in request_dict.keys()) and ("end" in request_dict.keys()):
            start_time = timezone.make_aware(datetime.utcfromtimestamp(int(request_dict["start"][0])),
                                             timezone.get_current_timezone())
            end_time = timezone.make_aware(datetime.utcfromtimestamp(int(request_dict["end"][0])),
                                           timezone.get_current_timezone())
            anomalies = Anomaly.objects.filter(timestamp__range=[start_time, end_time])
        if ("hasPeer" in request_dict.keys()):
            hasPeer = int(request_dict["hasPeer"][0])
            print("The hasPeer value is %d" % hasPeer)
    else:
        anomalies = Anomaly.objects.all()
    # template = loader.get_template('anomalyLocator/anomalies.html')
    anomaly_type = {'server': 0, 'client': 0, 'cloud network': 0, 'client network': 0, 'transit ISP': 0}
    for anomaly in anomalies:
        client = anomaly.client
        server = anomaly.server
        anomaly_hops = json.loads(anomaly.abnormal)
        anomaly_peer_num = len(json.loads(anomaly.peers))
        if anomaly_peer_num < hasPeer:
            # print("Excluding the anomaly because it has %d peers!" % anomaly_peer_num)
            continue
        anomaly_type_status = {'server': False, 'client': False, 'cloud network': False, 'client network': False,
                               'transit ISP': False}
        for anomaly_hop in anomaly_hops.keys():
            hop_type = anomaly_hops[anomaly_hop]['Type']
            anomaly_type_status[hop_type] = True
        for typ_key in anomaly_type_status.keys():
            if anomaly_type_status[typ_key]:
                anomaly_type[typ_key] += 1

    rsp = JsonResponse(anomaly_type, safe=False)
    rsp["Access-Control-Allow-Origin"] = "*"
    return rsp


@csrf_exempt
def anomalyCntPeerJson(request):
    url = request.get_full_path()
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if "days" in request_dict.keys():
            num_days = int(request_dict["days"][0])
            end_time = timezone.now()
            start_time = end_time - timedelta(days=num_days)
            # print(start_time)
            anomalies = Anomaly.objects.filter(timestamp__range=[start_time, end_time])
        elif "hours" in request_dict.keys():
            num_hours = int(request_dict["hours"][0])
            end_time = timezone.now()
            start_time = end_time - timedelta(hours=num_hours)
            anomalies = Anomaly.objects.filter(timestamp__range=[start_time, end_time])
        elif ("start" in request_dict.keys()) and ("end" in request_dict.keys()):
            start_time = timezone.make_aware(datetime.utcfromtimestamp(int(request_dict["start"][0])),
                                             timezone.get_current_timezone())
            end_time = timezone.make_aware(datetime.utcfromtimestamp(int(request_dict["end"][0])),
                                           timezone.get_current_timezone())
            anomalies = Anomaly.objects.filter(timestamp__range=[start_time, end_time])
    else:
        anomalies = Anomaly.objects.all()
    anomalyPeerCnt = {}
    for anomaly in anomalies:
        anomaly_peer_num = len(json.loads(anomaly.peers))
        for i in range(anomaly_peer_num + 1):
            if i not in anomalyPeerCnt.keys():
                anomalyPeerCnt[i] = 1
            else:
                anomalyPeerCnt[i] += 1
    rsp = JsonResponse(anomalyPeerCnt, safe=False)
    rsp["Access-Control-Allow-Origin"] = "*"
    return rsp


def anomalyGraph(request):
    url = request.get_full_path()
    latest_anomaly = Anomaly.objects.all()[0]
    anomaly_id = latest_anomaly.id
    if '?' in url:
        params = url.split('?')[1]
        request_dict = urllib.parse.parse_qs(params)
        if "id" in request_dict.keys():
            anomaly_id = int(request_dict["id"][0])
    template = loader.get_template('anomalyLocator/anomalyGraph.html')
    return HttpResponse(template.render({'id': anomaly_id}, request))

def anomalyGraphJson(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    if "id" in request_dict.keys():
        anomaly_id = int(request_dict["id"][0])
        anomaly_obj = Anomaly.objects.get(pk=anomaly_id)
    else:
        anomaly_obj = Anomaly.objects.all()[0]
    client = anomaly_obj.client
    server = anomaly_obj.server
    # print("Anomaly Client Server pair: (%s, %s)" % (client, server))
    abnormal_nodes = json.loads(anomaly_obj.abnormal)
    # print(abnormal_nodes)
    peers = json.loads(anomaly_obj.peers)
    # print(peers)
    node_list = []
    edge_list = []
    node_json = []
    edge_json = []
    suspect_nodes = []
    graph = {}
    try:
        client_obj = Client.objects.get(ip=client, server=server)
        client_route = Hop.objects.filter(client=client_obj).order_by('hopID')
        preID = -1
        for hop in client_route:
            # print("Processing node %s" % node.ip)
            node = hop.node
            if node.ip in abnormal_nodes.keys():
                curNode = {'name': node.name, 'group': 'Suspect'}
                suspect_nodes.append(node.name)
            else:
                curNode = {'name': node.name, 'group': 'Good'}
            if node.ip not in node_list:
                node_list.append(node.ip)
                node_json.append(curNode)
            curID = node_list.index(node.ip)
            if preID >= 0:
                if preID < curID:
                    edge_id = [preID, curID]
                else:
                    edge_id = [curID, preID]
                if edge_id not in edge_list:
                    edge_list.append(edge_id)
                    cur_edge = {}
                    cur_edge['source'] = edge_id[0]
                    cur_edge['target'] = edge_id[1]
                    cur_edge['value'] = 1
                    edge_json.append(cur_edge)
            preID = curID
        if len(suspect_nodes) == 1:
            node_json[node_list.index(suspect_nodes[0])]['group'] = 'Bad'
    except:
        print("Failed to parse anomaly's (%s,%s) route into json format!" % (client, server))
        pass

    for peer in peers:
        try:
            peer_obj = Client.objects.get(ip=peer['client'], server=peer['server'])
            peer_route = Hop.objects.filter(client=peer_obj).order_by('hopID')
            preID = -1
            for hop in peer_route:
                node = hop.node
                if node.ip in abnormal_nodes.keys():
                    curNode = {'name': node.name, 'group': 'Suspect'}
                else:
                    curNode = {'name': node.name, 'group': 'Good'}
                if node.ip not in node_list:
                    node_list.append(node.ip)
                    node_json.append(curNode)
                curID = node_list.index(node.ip)
                if preID >= 0:
                    if preID < curID:
                        edge_id = [preID, curID]
                    else:
                        edge_id = [curID, preID]
                    if edge_id not in edge_list:
                        edge_list.append(edge_id)
                        cur_edge = {}
                        cur_edge['source'] = edge_id[0]
                        cur_edge['target'] = edge_id[1]
                        cur_edge['value'] = 1
                        edge_json.append(cur_edge)
                preID = curID
        except:
            pass
    graph['nodes'] = node_json
    graph['links'] = edge_json
    rsp = JsonResponse(graph, safe=False)
    rsp["Access-Control-Allow-Origin"] = "*"
    return rsp


# Download all anomalies in csv files.
def downloadAnomaly(request):
    anomalies = Anomaly.objects.all()
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="anomalies.csv"'

    writer = csv.writer(response)
    writer.writerow(['timestamp', 'client', 'server', 'normal', 'abnormal', 'peers'])
    for anomaly in anomalies:
        writer.writerow(
            [int(time.mktime(anomaly.timestamp.timetuple())), anomaly.client, anomaly.server, anomaly.normal,
             anomaly.abnormal, anomaly.peers])
    return response


@csrf_exempt
def checkRoute(request):
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    # print(request_dict.keys())
    client_info = {}
    if ('client' in request_dict.keys()) and ('server' in request_dict.keys()):
        try:
            client_obj = Client.objects.get(ip=request_dict['client'][0], server=request_dict['server'][0])
            client_info = {'ip': client_obj.ip, 'server': client_obj.server}
        except:
            client_info = {}
    return JsonResponse(client_info)


@csrf_exempt
@transaction.atomic
def addRoute(request):
    if request.method == "POST":
        ## Update the client info
        # print(request.body)
        # start_time = time.time()
        client_info = json.loads(request.body.decode("utf-8"))
        try:
            client_obj = Client.objects.get(ip=client_info['ip'], server=client_info['server'])
            client_obj.name = client_info['name']
            client_obj.city = client_info['city']
            client_obj.region = client_info['region']
            client_obj.country = client_info['country']
            client_obj.AS = client_info['AS']
            client_obj.ISP = client_info['ISP']
            client_obj.latitude = client_info['latitude']
            client_obj.longitude = client_info['longitude']
            client_obj.route.clear()
        except:
            client_obj = Client(name=client_info['name'], ip=client_info['ip'], server=client_info['server'],
                                city=client_info['city'], region=client_info['region'], country=client_info['country'],
                                AS=client_info['AS'], ISP=client_info['ISP'], latitude=client_info['latitude'],
                                longitude=client_info['longitude'])
        client_obj.save()
        print("Client %s route length %d " % (client_obj.name, client_obj.route.count()))

        # time_elapsed = time.time() - start_time
        # print("1.1 The total time to process an add route request is : " + str(time_elapsed) + " seconds!")
        try:
            client_node_obj = Node.objects.get(ip=client_info['ip'])
            client_node_obj.name = client_info['name']
            client_node_obj.city = client_info['city']
            client_node_obj.region = client_info['region']
            client_node_obj.country = client_info['country']
            client_node_obj.AS = client_info['AS']
            client_node_obj.ISP = client_info['ISP']
            client_node_obj.latitude = client_info['latitude']
            client_node_obj.longitude = client_info['longitude']
            client_node_obj.nodeType = "client"
        except:
            client_node_obj = Node(name=client_info['name'], ip=client_info['ip'], city=client_info['city'],
                                   region=client_info['region'], country=client_info['country'], AS=client_info['AS'],
                                   ISP=client_info['ISP'], latitude=client_info['latitude'],
                                   longitude=client_info['longitude'], nodeType="client")
        client_node_obj.save()
        # client_obj.route.add(client_node_obj)
        hop_id = 0
        first_hop = Hop(client=client_obj, node=client_node_obj, hopID=hop_id)
        first_hop.save()
        print("Client %s route length %d " % (client_obj.name, client_obj.route.count()))
        # time_elapsed = time.time() - start_time
        # print("1.2 The total time to process an add route request is : " + str(time_elapsed) + " seconds!")

        ## Update all nodes' info in the route
        preNode = client_node_obj
        for i, node in enumerate(client_info['route']):
            node_ip = node['ip']
            if node_ip == client_info['server']:
                node_type = "server"
            else:
                node_type = "router"
            try:
                node_obj = Node.objects.get(ip=node_ip)
                node_obj.name = node['name']
                node_obj.city = node['city']
                node_obj.region = node['region']
                node_obj.country = node['country']
                node_obj.AS = node['AS']
                node_obj.ISP = node['ISP']
                node_obj.latitude = node['latitude']
                node_obj.longitude = node['longitude']
                node_obj.nodeType = node_type
            except:
                node_obj = Node(name=node['name'], ip=node['ip'], city=node['city'], region=node['region'],
                                country=node['country'], AS=node['AS'], ISP=node['ISP'], latitude=node['latitude'],
                                longitude=node['longitude'], nodeType=node_type)

            node_obj.save()
            hop_id += 1
            cur_hop = Hop(client=client_obj, node=node_obj, hopID=hop_id)
            cur_hop.save()
            # client_obj.route.add(node_obj)
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
        # client_obj.save()
        # time_elapsed = time.time() - start_time
        # print("3. The total time to process an add route request is : " + str(time_elapsed) + " seconds!")
        return index(request)
    else:
        return HttpResponse(
            "Please use the POST method for http://locator_ip/anomalyLocator/addRoute request to add new routes for a client!")


@csrf_exempt
@transaction.atomic
def updateRoute(request):
    # time_start = time.time()
    isUpdated = False
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    # print(request_dict.keys())
    if ('client' in request_dict.keys()) and ('server' in request_dict.keys()) and ('qoe' in request_dict.keys()):
        client = request_dict['client'][0]
        server = request_dict['server'][0]
        qoe = float(request_dict['qoe'][0])
        state = True
        update = Update(client=client, server=server, qoe=qoe, state=state)
        update.save()
        isUpdated = update_route(client, server, update)
    # time_elapsed = time.time() - time_start
    # print("The processing time of the updateRoute request is %s seconds" % time_elapsed)
    if isUpdated:
        return HttpResponse("Yes")
    else:
        return HttpResponse("No")


@csrf_exempt
@transaction.atomic
def locate(request):
    time_start = time.time()
    url = request.get_full_path()
    params = url.split('?')[1]
    request_dict = urllib.parse.parse_qs(params)
    # print(request_dict.keys())
    anomaly_info = {}
    if ('client' in request_dict.keys()) and ('server' in request_dict.keys()) and ('qoe' in request_dict.keys()):
        client = request_dict['client'][0]
        server = request_dict['server'][0]
        qoe = float(request_dict['qoe'][0])
        state = False
        update = Update(client=client, server=server, qoe=qoe, state=state)
        update.save()
        anomaly_info = locate_anomaly(client, server, update)

        ## Add the anomaly to database
        if anomaly_info:
            normal_nodes_str = json.dumps(anomaly_info['normal'])
            abnormal_nodes_str = json.dumps(anomaly_info['abnormal'])
            peers_str = json.dumps(anomaly_info['peers'])
            time_elapsed = time.time() - time_start
            new_anomaly = Anomaly(client=client, normal=normal_nodes_str, abnormal=abnormal_nodes_str, peers=peers_str,
                                  server=server, timeToLocate=time_elapsed)
            new_anomaly.save()
    print("Locate request processing time: %s seconds!" % time_elapsed)
    return JsonResponse(anomaly_info)
