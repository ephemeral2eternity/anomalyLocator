## route_utils.py
# By Chen Wang, March 4, 2016
import datetime
from anomalyLocator.models import Client, Node, Update

def route2str(full_route):
    route_list = []
    for node in full_route:
        route_list.append(node['ip'])

    route_str = '-'.join(str(e) for e in route_list)
    return route_str


def update_route(client_ip, server_ip, update):
    isUpdated = False
    try:
        client_obj = Client.objects.get(ip=client_ip, server=server_ip)
        route = client_obj.route.all()
        for node in route:
            # print("Reading info for node %s " % node.ip)
            try:
                # print("Removing updates from the same client %s for node %s " % (update.client, node.ip))
                update_client_exist = node.updates.get(client=update.client, server=update.server)
                node.updates.remove(update_client_exist)
                # print("Removing updates successfully!")
            except:
                pass
            while node.updates.count() > 2:
                oldest_obj = node.updates.all().order_by('timestamp')[0]
                node.updates.remove(oldest_obj)
            # print("Adding update from client %s with QoE %.2f to node %s " % (update.client, update.qoe, node.ip))
            node.updates.add(update)
        isUpdated = True
    except:
        isUpdated = False
        print("The update_route cannot find client:" + client_ip + " and server:" + server_ip + " in Client Table!")
    return isUpdated


def getNodeType(node_ip, node_AS, client_ip, client_AS, server_ip, server_AS):
    if node_ip == client_ip:
        node_type = 'client'
    elif node_ip == server_ip:
        node_type = 'server'
    elif node_AS == client_AS:
        node_type = 'client network'
    elif node_AS == server_AS:
        node_type = 'cloud network'
    else:
        node_type = 'transit ISP'
    return node_type


def locate_anomaly(client_ip, server_ip, update):
    normal_hops = {}
    abnormal_hops = {}
    peers = []
    past_min_datetime = datetime.datetime.now() - datetime.timedelta(minutes=1)
    try:
        client_obj = Client.objects.get(ip=client_ip, server=server_ip)
        client_AS = client_obj.AS
        server_obj = Node.objects.get(ip=server_ip)
        server_AS = server_obj.AS
        route = client_obj.route.all()
        for node in route:
            # print("Checking update timestamp for node : %s" % node.ip)
            try:
                update_client_exist = node.updates.filter(client=update.client,server=update.server)
                for u in update_client_exist:
                      node.updates.remove(u)
            except:
                pass

            node_updates = node.updates.all().order_by('-timestamp')

            if node_updates.count() == 0:
                node_type = getNodeType(node.ip, node.AS, client_ip, client_AS, server_ip, server_AS)
                abnormal_hops[node.ip] = {'Name' : node.name, 'Type' : node_type, 'AS' : node.AS, 'ISP' : node.ISP}
                # print("Abnormal Hop Added: %s" % node.ip)
                node.updates.add(update)
                continue

            recent_update = node_updates[0]
            recent_ts = recent_update.timestamp
            # print("The most recent update timestamp is: %s and the previous minute ts is: %s" % (recent_ts, past_min_datetime))
            recent_state = recent_update.state
            recent_client = recent_update.client
            recent_server = recent_update.server
            recent_datetime = datetime.datetime(recent_ts.year, recent_ts.month, recent_ts.day, recent_ts.hour, recent_ts.minute, recent_ts.second)
            if (recent_datetime > past_min_datetime) and recent_state:
                node_type = getNodeType(node.ip, node.AS, client_ip, client_AS, server_ip, server_AS)
                normal_hops[node.ip] = {'Name' : node.name, 'Type' : node_type, 'AS' : node.AS, 'ISP' : node.ISP}
                # print("Normal Hop Added: %s" % node.ip)
                cur_peer = {'client' : recent_client, 'server' : recent_server}
                if cur_peer not in peers:
                      peers.append({'client':recent_client, 'server':recent_server})
                # print("Peer added (%s, %s)" % (recent_client, recent_server))
            else:
                node_type = getNodeType(node.ip, node.AS, client_ip, client_AS, server_ip, server_AS)
                abnormal_hops[node.ip] = {'Name' : node.name, 'Type' : node_type, 'AS' : node.AS, 'ISP' : node.ISP}
                # print("Abnormal Hop Added: %s" % node.ip)
            while node.updates.count() > 2:
                oldest_update = node.updates.order_by('timestamp')[0]
                node.updates.remove(oldest_update)
            node.updates.add(update)
        anomaly_info = {'client':client_ip, 'normal':normal_hops, 'abnormal':abnormal_hops, 'peers':peers}
        # print(anomaly_info)
    except:
        anomaly_info = {}
    return anomaly_info
