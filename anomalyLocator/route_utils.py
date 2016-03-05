## route_utils.py
# By Chen Wang, March 4, 2016
from anomalyLocator.models import Client, Node

def route2str(full_route):
    route_list = []
    for node in full_route:
        route_list.append(node['ip'])

    route_str = ','.join(str(e) for e in route_list)
    return route_str

def update_route(client_route_str):
    nodes = client_route_str.split(',')
    for node_ip in nodes:
        try:
            node_obj = Client.objects.get(ip=node_ip)
        except:
            node_obj = Client(ip=node_ip)
        node_obj.save()
