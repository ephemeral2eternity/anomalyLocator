from anomalyDiagnosis.models import Node, User, ISP, Session, DeviceInfo, Network, Hop, Subnetwork, Edge, NetEdge, PeeringEdge
from anomalyDiagnosis.models import Event, Path
from django.db import transaction
from anomalyDiagnosis.ipinfo import *

def add_related_session(session):
    for node in session.route.all():
        if session not in node.related_sessions.all():
            node.related_sessions.add(session)
            node.save()

    for net in session.sub_networks.all():
        if session not in net.related_sessions.all():
            net.related_sessions.add(session)
            net.save()


### @function add_node(node_ip, nodeTyp="router")
#   @params:
#       node_ip : the ip address of a given node
#       nodeTyp : the type of a given node. Can be client, server, router in a video session
#                 or pl_agent, which is a probing agent in PlanetLab
#                 or azure_agent, which is a probing agent in Azure
#   @return: the node object in Node model
@transaction.atomic
def add_node(node_ip, nodeTyp="router", nodeName=None, netTyp="transit"):
    try:
        node = Node.objects.get(ip=node_ip)
    except:
        node_info = get_node_info(node_ip)

        try:
            node_isp = ISP.objects.get(ASNumber=node_info["AS"])
        except:
            node_isp = ISP(ASNumber=node_info["AS"], name=node_info["ISP"], type=netTyp)
            node_isp.save()

        latitude = float(node_info['latitude'])
        latitude_str = '{0:.6f}'.format(latitude)
        longitude = float(node_info['longitude'])
        longitude_str = '{0:.6f}'.format(longitude)
        # print("AS " + str(node_isp.ASNumber) + "(" + latitude_str + "," + longitude_str + ")" )
        try:
            node_network = Network.objects.get(isp=node_isp, latitude=latitude_str, longitude=longitude_str)
        except:
            node_network = Network(isp=node_isp, latitude=latitude_str, longitude=longitude_str, city=node_info["city"], region=node_info["region"], country=node_info["country"])
            node_network.save()

        if nodeName:
            node = Node(ip=node_ip, name=nodeName, type=nodeTyp, network=node_network)
        else:
            node = Node(ip=node_ip, name=node_info['name'], type=nodeTyp, network=node_network)
        node.save()

        if node not in node_network.nodes.all():
            node_network.nodes.add(node)
            node_network.save()

        if node_network not in node_isp.networks.all():
            node_isp.networks.add(node_network)
            node_isp.save()

    return node

### @function add_session(client, server)
#   @params:
#       client : the client node object of the session
#       server : the server node object of the session
@transaction.atomic
def add_session(client, server):
    try:
        session = Session.objects.get(client=client, server=server)
    except:
        session = Session(client=client, server=server)
        session.save()
    return session

### add_hop(hop, hop_id, session)
#   @description: add the current node object as a hop in the session
#   @params:
#       hop : the node object of current hop
#       hop_id : The hop id of current id in the session
#       session : The session the hop is on.
def add_hop(hop, hop_id, session):
    ## Add hop of current node
    try:
        cur_hop = Hop.objects.get(node=hop, hopID=hop_id, session=session)
    except:
        cur_hop = Hop(node=hop, hopID=hop_id, session=session)
        cur_hop.save()


### add_subnet(node_net, net_id, session)
#   @description: add the current network object as a subnet in the session
#   @params:
#       node_net : the network object
#       net_id : the sequence number of the network in the session
#       session : The session the network is on.
def add_subnet(node_net, net_id, session):
    try:
        cur_net = Subnetwork.objects.get(network=node_net, netID=net_id, session=session)
    except:
        cur_net = Subnetwork(network=node_net, netID=net_id, session=session)
        cur_net.save()

### @function update_peering(src_isp, dst_isp)
#   @descr: Save the peering relationship in the database
#   @params:
#       src_isp : the source ISP in the peering link
#       dst_isp : the destination ISP in the peering link
@transaction.atomic
def update_peering(src_isp, dst_isp):
    if src_isp.ASNumber == dst_isp.ASNumber:
        return

    if src_isp.ASNumber > dst_isp.ASNumber:
        tmp_isp = src_isp
        src_isp = dst_isp
        dst_isp = tmp_isp

    try:
        peering_link = PeeringEdge.objects.get(srcISP=src_isp, dstISP=dst_isp)
    except:
        peering_link = PeeringEdge(srcISP=src_isp, dstISP=dst_isp)
        peering_link.save()

### @function update_net_edge(srcNet, dstNet, isIntra)
#   @descr: Save the edge between two networks in the database
#   @params:
#       srcNet : the source network of the link
#       dstNet : the destination network of the link
#       isIntra : denotes if the link is an intra ISP link
@transaction.atomic
def update_net_edge(srcNet, dstNet, isIntra):
    if srcNet.id == dstNet.id:
        return

    if srcNet.id > dstNet.id:
        tmpNet = srcNet
        srcNet = dstNet
        dstNet = tmpNet

    try:
        net_edge = NetEdge.objects.get(srcNet=srcNet, dstNet=dstNet)
    except:
        net_edge = NetEdge(srcNet=srcNet, dstNet=dstNet, isIntra=isIntra)
        net_edge.save()

### @function update_edge(src_node, dst_node, latency)
#   @params:
#       src_node : the source node obj
#       dst_node: the destination node obj
@transaction.atomic
def update_edge(src_node, dst_node):
    if src_node.ip == dst_node.ip:
        return

    if src_node.ip > dst_node.ip:
        tmp_node = src_node
        src_node = dst_node
        dst_node = tmp_node

    try:
        link = Edge.objects.get(src=src_node, dst=dst_node)
    except:
        link_is_intra = (src_node.network.isp.ASNumber == dst_node.network.isp.ASNumber)
        link = Edge(src=src_node, dst=dst_node, isIntra=link_is_intra)
        link.save()

        # Add peering link if necessary
        if not link_is_intra:
            update_peering(src_node.network.isp, dst_node.network.isp)

        # Add network_edge if neccessary
        if src_node.network.id != dst_node.network.id:
            update_net_edge(src_node.network, dst_node.network, link_is_intra)
    return link

### @function add_server_to_user(server_node, user)
#   @params:
#       server_node : the server node obj
#       dst_node: the user obj
#   @return: return the updated user obj
def update_server_for_user(server_node, user):
    if user.server != server_node:
        srv_event = Event(user_id=user.id, type="SRV_CHANGE", prevVal=user.server.ip, curVal=server_node.ip)
        srv_event.save()
        user.events.add(srv_event)
    user.server = server_node
    return user

### @function add_user(client_node, device_info)
#   @params:
#       client_node : the user's client node
#       device_info: the user's device info
#   @return: return the updated user obj
@transaction.atomic
def add_user(session, device_info):
    try:
        device = DeviceInfo.objects.get(device=device_info['device'], os=device_info['os'],
                                        player=device_info['player'], browser=device_info['browser'])
    except:
        device = DeviceInfo(device=device_info['device'], os=device_info['os'],
                            player=device_info['player'], browser=device_info['browser'])
        device.save()

    # Update User Info
    try:
        user = User.objects.get(client=session.client)
        user_existed = True

        if user.device != device:
            pre_device = user.device
            device_event = Event(user_id=user.id, type="DEVICE_CHANGE", prevVal=str(user.device), curVal=str(device))
            device_event.save()
            user.device = device
            user.events.add(device_event)

            if user in pre_device.users.all():
                pre_device.users.remove(user)
    except:
        user = User(client=session.client, server=session.server, device=device)
        user_existed = False
        user.save()

    if user not in device.users.all():
        device.users.add(user)
        device.save()

    if session not in user.sessions.distinct():
        user.sessions.add(session)
        user.save()

    if user_existed:
        user = update_server_for_user(session.server, user)
        user.save()

### @function add_path(session)
#   @params: path_len ---- the length of the session path
def add_path(session, path_len):
    try:
        curPath = Path.objects.get(session_id=session.id, length=path_len)
    except:
        curPath = Path(session_id=session.id, length=path_len)
        curPath.save()
    session.path = curPath
    session.save()


### @function add_route(route)
#   @params:
#       route : a json object of a traceroute session info
#               The key denotes the hop number. 0 denotes the client and the maximum key denotes the server
#               Each value object contains info {"ip": hop_ip_x.x.x.x, "name": hop_hostname, "time": time_to_get_to_the_hop}
def add_route(client_info):
    route = client_info['route']
    device_info = client_info['device']
    hop_ids = sorted(route.keys(), key=int)
    client = route[hop_ids[0]]
    server = route[hop_ids[-1]]
    if (client['ip'] == "*") or (server["ip"] == "*"):
        return

    client_node = add_node(client["ip"], "client", client["name"], "access")
    server_node = add_node(server["ip"], "server", server["name"], "cloud")

    session = add_session(client_node, server_node)
    add_user(session, device_info)
    sub_net_id = 0
    add_hop(client_node, int(hop_ids[0]), session)
    add_subnet(client_node.network, sub_net_id, session)

    pre_node = client_node
    for hop_id in hop_ids[1:-1]:
        cur_hop = route[hop_id]
        if (cur_hop["ip"] == "*") or (is_reserved(cur_hop["ip"])):
            continue

        cur_node = add_node(cur_hop["ip"])

        update_edge(pre_node, cur_node)
        add_hop(cur_node, hop_id, session)
        if cur_node.network.id != pre_node.network.id:
            sub_net_id += 1
            add_subnet(cur_node.network, sub_net_id, session)

        pre_node = cur_node

    update_edge(pre_node, server_node)
    add_hop(server_node, int(hop_ids[-1]), session)

    add_path(session, max(hop_ids))

    if server_node.network.id != pre_node.network.id:
        sub_net_id += 1
        add_subnet(server_node.network, sub_net_id, session)

    add_related_session(session)