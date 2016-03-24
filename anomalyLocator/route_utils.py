## route_utils.py
# By Chen Wang, March 4, 2016
import datetime
from anomalyLocator.models import Client, Node

def route2str(full_route):
    route_list = []
    for node in full_route:
        route_list.append(node['ip'])

    route_str = '-'.join(str(e) for e in route_list)
    return route_str


def update_route(client_ip, client_route_str):
    nodes = client_route_str.split('-')
    srv_ip = nodes[-1]
    try:
        client_obj = Client.objects.get(ip=client_ip, server=srv_ip)
        client_obj.save()
        #print("The update_route find route from client" + client_ip + " to server " + srv_ip + " and update the client check time!")
    except:
        #print("The update_route cannot find route from client" + client_ip + " to server " + srv_ip + " and cannot update client check time!")
    for node_ip in nodes:
        try:
            node_obj = Node.objects.get(ip=node_ip)
            node_obj.save()
            #print("The update_route find node" + node_ip + " in existing cache!")
        except:
            #print("The update_route cannot find node" + node_ip + " in existing cache!")


def locate_anomaly(client_ip, client_route_str):
    nodes = client_route_str.split('-')
    print("All nodes in client route in locate_anomaly:" + client_route_str)
    normal_hops = []
    abnormal_hops = []
    abnormal_hops.append(client_ip)
    peers = []
    srv_ip = nodes[-1]
    try:
        client_obj = Client.objects.get(ip=client_ip, server=srv_ip)
        client_update_time = client_obj.latest_update
        client_update_datetime = datetime.datetime(client_update_time.year, client_update_time.month, client_update_time.day, client_update_time.hour, client_update_time.minute, client_update_time.second)
    except:
        client_update_datetime = datetime.datetime.now() - datetime.timedelta(minutes=1)

    past_min_datetime = datetime.datetime.now() - datetime.timedelta(minutes=1)
    if client_update_datetime > past_min_datetime:
        cmp_update_datetime = client_update_datetime
    else:
        cmp_update_datetime = past_min_datetime

    for node_ip in nodes:
        print("Get latest time for node:" + node_ip)
        try:
            node_obj = Node.objects.get(ip=node_ip)
            node_update_time = node_obj.latest_check
            node_update_datetime = datetime.datetime(node_update_time.year, node_update_time.month, node_update_time.day, node_update_time.hour, node_update_time.minute, node_update_time.second)
            #print("Latest check time for node " + node_ip + " is " + node_update_datetime.strftime("%Y-%m-%d %H:%M:%S"))
            if node_update_datetime > cmp_update_datetime:
                normal_hops.append(node_ip)
            else:
                abnormal_hops.append(node_ip)
            node_clients = node_obj.clients.split('-')
            for peer_ip in node_clients:
                if (peer_ip != client_ip) and (peer_ip not in peers):
                       peers.append(peer_ip)
        except:
            #print("Ingoring node: " + node_ip + " as it is not cached as it belongs to client whose route has not been cached!")
    anomaly_info = {'client':client_ip, 'normal':normal_hops, 'abnormal':abnormal_hops, 'peers':peers}
    return anomaly_info
