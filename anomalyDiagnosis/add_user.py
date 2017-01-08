from anomalyDiagnosis.models import Node, User, Session, Server, DeviceInfo, Network, Hop, Subnetwork, Edge, NetEdge
from anomalyDiagnosis.models import Event, Path

def add_user(client_info):
    ############################################################################################################
    ## Update the client side network and node
    # Update the client network
    try:
        client_network = Network.objects.get(ASNumber=client_info['AS'],
                                             latitude=client_info['latitude'], longitude=client_info['longitude'])
    except:
        client_network = Network(type="access", name=client_info['ISP'], ASNumber=client_info['AS'],
                                 latitude=client_info['latitude'], longitude=client_info['longitude'],
                                 city=client_info['city'], region=client_info['region'], country=client_info['country'])
    client_network.save()

    # Update the client node
    try:
        client_node = Node.objects.get(ip=client_info['ip'])
        client_node.type = 'client'
        client_node.name = client_info['name']
        client_node.network_id = client_network.id
    except:
        client_node = Node(name=client_info['name'], ip=client_info['ip'], type='client', network_id=client_network.id)
    client_node.save()

    ###############################################################################################################
    ## Update the user and the device
    #  Update Device Info
    device_info = client_info['device']
    try:
        device = DeviceInfo.objects.get(device=device_info['device'], os=device_info['os'],
                                        player=device_info['player'], browser=device_info['browser'])
    except:
        device = DeviceInfo(device=device_info['device'], os=device_info['os'],
                            player=device_info['player'], browser=device_info['browser'])
    device.save()

    ###############################################################################################################
    ## Update the server side object, node and network
    # Update server network
    server_info = client_info['server']
    try:
        srv_network = Network.objects.get(ASNumber=server_info['AS'],
                                          latitude=server_info['latitude'], longitude=server_info['longitude'])
    except:
        srv_network = Network(type="cloud", name=server_info['ISP'], ASNumber=server_info['AS'],
                              latitude=server_info['latitude'], longitude=server_info['longitude'],
                              city=server_info['city'], region=server_info['region'], country=server_info['country'])
    srv_network.save()

    ## Update server node
    try:
        server_node = Node.objects.get(ip=server_info['ip'])
        server_node.name = server_info['name']
        server_node.type = "server"
        server_node.network_id = srv_network.id
    except:
        server_node = Node(ip=server_info['ip'], name=server_info['name'], type="server", network_id=srv_network.id)
    server_node.save()

    ## Update Server Object
    try:
        server = Server.objects.get(ip=server_info['ip'])
    except:
        server = Server(ip=server_info['ip'])
    server.save()

    # Update User Info
    try:
        user = User.objects.get(ip=client_info['ip'])
        user_existed = True

        if user.device != device:
            device_event = Event(user_id=user.id, type="DEVICE_CHANGE", prevVal=str(user.device), curVal=str(device))
            device_event.save()
            user.device = device
            user.events.add(device_event)
    except:
        user = User(ip=client_info['ip'], device=device, name=client_info['name'])
        user_existed = False

    if user_existed:
        if user.server != server:
            srv_event = Event(user_id=user.id, type="SRV_CHANGE", prevVal=user.server.ip, curVal=server.ip)
            srv_event.save()
            user.events.add(srv_event)
    else:
        user.server = server

    ###############################################################################################################
    ## Update the session route, subnetworks and path
    # Update session object
    try:
        session = Session.objects.get(client_ip=client_info['ip'], server_ip=server_info['ip'])
        session_exist = True
        print("Update existing session " + str(session))
    except:
        session = Session(client_ip=client_info['ip'], server_ip=server_info['ip'])
        session_exist = False
        print("Add new session " + str(session))
    session.save()
    user.save()

    ## Session update route
    hop_id = 0
    try:
        client_hop = Hop.objects.get(session=session, node=client_node, hopID=hop_id)
    except:
        client_hop = Hop(session=session, node=client_node, hopID=hop_id)
    client_hop.save()

    ## Session update subnetwork
    net_id = 0
    try:
        client_subnet = Subnetwork.objects.get(session=session, network=client_network, netID=net_id)
    except:
        client_subnet = Subnetwork(session=session, network=client_network, netID=net_id)
    client_subnet.save()

    ## Update all nodes' info in the route
    preNode = client_node
    preNet = client_network
    route_updated = False
    for i, node in enumerate(client_info['route']):
        node_ip = node['ip']

        if node_ip == client_info['ip']:
            continue

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
            node_network = Network(type=net_type, ASNumber=node['AS'], name=node['ISP'],
                                   latitude=node['latitude'], longitude=node['longitude'],
                                   city=node['city'], region=node['region'], country=node['country'])
        node_network.save()

        if node_obj not in node_network.nodes.all():
            node_network.nodes.add(node_obj)
            node_network.save()

        node_obj.network_id = node_network.id
        node_obj.save()

        ## save current hop to a route
        hop_id += 1
        try:
            cur_hop = Hop.objects.get(session=session, node=node_obj, hopID=hop_id)
        except:
            cur_hop = Hop(session=session, node=node_obj, hopID=hop_id)
            if session_exist:
                org_hop = Hop.objects.filter(session=session, hopID=hop_id).latest()
                node_event = Event(user_id=user.id, type="ROUTE_CHANGE", prevVal=org_hop.node.ip, curVal=node_obj.id)
                node_event.save()
                user.events.add(node_event)

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

        ## Update subnetworks for the session.
        if (node_network.id != preNet.id):
            net_id += 1
            try:
                cur_subnet = Subnetwork.objects.get(session=session, network=node_network, netID=net_id)
            except:
                cur_subnet = Subnetwork(session=session, network=node_network, netID=net_id)
                if session_exist:
                    org_subnet = Subnetwork.objects.filter(session=session, netID=net_id).latest()
                    net_event = Event(user_id=user.id, type="NET_CHANGE", prevVal=org_subnet.network.id,
                                       curVal=node_network.id)
                    net_event.save()
                    user.events.add(net_event)
            cur_subnet.save()

            ## Add NetEdge object
            curNet = node_network
            if curNet.id < preNet.id:
                srcNet = curNet
                dstNet = preNet
            else:
                srcNet = preNet
                dstNet = curNet

            try:
                net_edge = NetEdge.objects.get(srcNet=srcNet, dstNet=dstNet)
            except:
                net_edge = NetEdge(srcNet=srcNet, dstNet=dstNet)
            net_edge.save()
            preNet = curNet

    cur_path_len = hop_id + 1
    try:
        cur_path = Path.objects.get(session_id=session.id, length=cur_path_len)
    except:
        cur_path = Path(session_id=session.id, length=cur_path_len)
    cur_path.save()
    session.path = cur_path
    session.save()

    if session not in user.sessions.all():
        user.sessions.add(session)
    user.save()