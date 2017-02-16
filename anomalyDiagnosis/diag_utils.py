## diag_utils.py
# By Chen Wang, Jan 3, 2017
import datetime
import time
import socket
import requests
import json
from anomalyDiagnosis.models import Node, Network, DeviceInfo, User, Session, Event, Anomaly, Cause, Path
from anomalyDiagnosis.thresholds import *
from anomalyDiagnosis.ipinfo import *

def get_exp_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('google.com', 0))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"

def get_ipinfo(ip):
    try:
        url = "http://manage.cmu-agens.com/nodeinfo/get_node?" + ip
        rsp = requests.get(url)
        node_info = json.loads(rsp.text)
    except:
        node_info = ipinfo(ip)
        node_info["name"] = node_info["hostname"]
    return node_info

def update_attributes(client_ip, server_ip, update):
    isUpdated = False

    ## Get client_node
    try:
        client_node = Node.objects.get(ip=client_ip)

        ## Get user
        try:
            user = User.objects.get(client=client_node)
            if user.device:
                user.device.updates.add(update)
                user.device.device_qoe_score = (1 - alpha) * float(user.device.device_qoe_score) + alpha * float(update.qoe)
                # print("Device QoE Score: %.4f" % user.device.device_qoe_score)
                user.device.save()

            user.save()

            user_updated = True
            print("Successfully update user with " + client_ip)
        except:
            user_updated = False
            print("Cannot obtain user with ip: " + client_ip)
    except:
        user_updated = False
        print("Cannot obtain user with ip: " + client_ip)

    try:
        session = Session.objects.get(client_ip=client_ip, server_ip=server_ip)
        session.updates.add(update)
        for network in session.sub_networks.all():
            network.updates.add(update)
            network.network_qoe_score = (1 - alpha) * float(network.network_qoe_score) + alpha * float(update.qoe)
            # print("Network QoE Score: %.4f" % network.network_qoe_score)
            network.save()

        for node in session.route.all():
            node.updates.add(update)
            node.node_qoe_score = (1 - alpha) * float(node.node_qoe_score) + alpha * float(update.qoe)
            # print("Node QoE Score: %.4f" % node.node_qoe_score)
            node.save()

        session.save()
        session_updated = True
        print("Successfully send update for session: "+ client_ip + "<--->" + server_ip)
    except:
        session_updated = False
        print("Failed to send update for session: " + client_ip + "<--->" + server_ip)

    return (user_updated and session_updated)

def add_event(client_ip, event_dict):
    try:
        client_node = Node.objects.get(ip=client_ip)
        try:
            user = User.objects.get(client=client_node)
            event = Event(user_id=user.id, type=event_dict['type'], prevVal=event_dict['prevVal'], curVal=event_dict['curVal'])
            event.save()
            user.events.add(event)

            if str(event_dict['type']).startswith("SRV"):
                try:
                    srv = Node.objects.get(ip=event_dict['curVal'])
                except:
                    srv_info = get_ipinfo(event_dict['curVal'])
                    try:
                        srv_network = Network.objects.get(ASNumber=srv_info["AS"], latitude=srv_info["latitude"], longitude=srv_info["longitude"])
                    except:
                        srv_network = Network(name=srv_info["ISP"], ASNumber=srv_info["AS"],
                                              latitude=srv_info["latitude"], longitude=srv_info["longitude"],
                                              city=srv_info["city"], region=srv_info["region"], country=srv_info["country"])
                        srv_network.save()

                    srv = Node(ip=event_dict['curVal'], type="server", name=event_dict['curVal'], network_id=srv_network.id)
                    srv.save()
                user.server = srv

            if str(event_dict['type']).startswith("DEVICE"):
                device_vals = event_dict['curVal'].split(',')
                try:
                    device = DeviceInfo.objects.get(device=device_vals[0], os=device_vals[1], player=device_vals[2], browser=device_vals[3])
                except:
                    device = DeviceInfo(device=device_vals[0], os=device_vals[1], player=device_vals[2], browser=device_vals[3])
                    device.save()
                user.device = device

            user.save()
            isAdded = True
        except:
            isAdded = False
            print("Failed to obtain user with ip %s to add event %s" % (client_ip, event_dict['type']))
    except:
        isAdded = False
        print("Failed to obtain client node with ip %s to add event %s!" % (client_ip, event_dict['type']))

    return isAdded

def check_status(updates, session_id):
    for update in updates.all():
        if update.satisfied and (update.session_id != session_id):
            return False, update
    return True, None

def check_path_length(curPathLength, cur_time):
    ## Long path issues
    path_time_window_start = cur_time - datetime.timedelta(hours=path_time_window)
    all_paths = Path.objects.filter(timestamp__range=(path_time_window_start, cur_time))
    ordered_paths = all_paths.order_by('-length')

    rank = 0
    for tmp_path in ordered_paths.all():
        if tmp_path.length > curPathLength:
            rank += 1
        else:
            break

    long_path_issue = 1 - float(rank)/all_paths.count()
    return long_path_issue

def get_suspect_prob(updates):
    cur_time = datetime.datetime.now()
    time_window_start = cur_time - datetime.timedelta(minutes=network_time_window)
    recent_updates = updates.filter(timestamp__range=(time_window_start, cur_time))

    total = recent_updates.count()
    unsatisfied = 0
    for update in recent_updates.all():
        if not update.satisfied:
            unsatisfied += 1

    if total != 0:
        prob = float(unsatisfied) / total
    else:
        prob = 1.0
    return prob


def get_ave_QoE(updates, ts_start, ts_end):
    requested_updates = updates.filter(timestamp__range=(ts_start, ts_end))

    total = requested_updates.count()
    total_qoe = 0.0
    for update in requested_updates.all():
        total_qoe += float(update.qoe)

    if total != 0:
        aveQoE = float(total_qoe)/total
    else:
        aveQoE = -1.0
    return  aveQoE


def get_suspects(session):
    cur_time = datetime.datetime.now()
    time_window_start = cur_time - datetime.timedelta(minutes=node_time_window)
    suspect_nodes = []
    related_sessions = []
    for node in session.route.all():
        recent_updates = node.updates.filter(timestamp__range=(time_window_start, cur_time))
        suspect, update = check_status(recent_updates, session.id)
        if not suspect:
            if update.session_id not in related_sessions:
                related_sessions.append(update.session_id)
            continue
        else:
            suspect_nodes.append(node)
    return suspect_nodes, related_sessions


def diagnose(client_ip, server_ip, qoe, anomalyTyp):
    diagRst = {}

    ## Get client_node
    try:
        client_node = Node.objects.get(ip=client_ip)

        try:
            user = User.objects.get(client=client_node)
        except:
            diagRst['error'] = "No user with " + client_ip + " in database!"
            return diagRst
    except:
        diagRst['error'] = "No node with " + client_ip + " in database!"
        return diagRst

    try:
        session = Session.objects.get(client_ip=client_ip, server_ip=server_ip)
    except:
        diagRst['error'] = "No session " + client_ip + "<--->" + server_ip + " in database!"
        return diagRst

    anomaly = Anomaly(user_id=user.id, session_id=session.id, qoe=qoe, type=anomalyTyp)
    anomaly.save()

    cur_time = datetime.datetime.now()
    cur_timestamp = cur_time.timestamp()

    suspect_nodes, related_sessions = get_suspects(session)

    related_sessions_str = ",".join(str(x) for x in related_sessions)
    anomaly.related_sessions = related_sessions_str

    ## Diagnose the probability of the suspect nodes.
    processed = []
    causes_list = []
    for node in suspect_nodes:
        if node.type == "client":
            attribute = "device"
            attribute_id = user.device.id
            attribute_value = str(user.device)
            attribute_qoe_score = user.device.device_qoe_score
            updates = user.client.updates
        elif node.type == "server":
            attribute = "server"
            attribute_id = user.server.id
            attribute_value = str(user.server)
            attribute_qoe_score = user.server.node_qoe_score
            updates = user.server.updates
        else:
            attribute = "network"
            attribute_id = node.network_id
            node_network = Network.objects.get(id=node.network_id)
            attribute_value = str(node_network)
            attribute_qoe_score = node_network.network_qoe_score
            updates = node_network.updates

        processed_code = attribute + "_" + str(attribute_id)
        if processed_code not in processed:
            prob = get_suspect_prob(updates)
            cause = Cause(node=node, attribute=attribute, attribute_id=attribute_id, attribute_value=attribute_value,
                      prob=prob, attribute_qoe_score=attribute_qoe_score)
            cause.save()
            causes_list.append({"node": str(node), "node_id": node.id, "attribute": attribute, "attribute_id":attribute_id, "value": attribute_value, "prob": prob})
            anomaly.causes.add(cause)
            processed.append(processed_code)

    ## Check event proximity
    event_time_window_start = cur_time - datetime.timedelta(minutes=event_time_window)
    for event in user.events.filter(timestamp__range=(event_time_window_start, cur_time)).all():
        prob = 1 - (cur_timestamp - event.timestamp.timestamp())/float(event_time_window*60)
        attribute = "event"
        attribute_id = event.id
        cause = Cause(attribute=attribute, attribute_id=attribute_id, attribute_value=str(event), prob=prob)
        cause.save()
        causes_list.append({"attribute": attribute, "attribute_id": attribute_id, "value": str(event), "prob": prob})
        anomaly.causes.add(cause)

    long_path = check_path_length(session.path.length, cur_time)
    # element_status["path_" + str(session.path.length)] = long_path
    if long_path > 0.8:
        attribute = "path"
        attribute_id = session.path.id
        prob = long_path
        cause = Cause(attribute=attribute, attribute_id=attribute_id, attribute_value=str(session.path), prob=prob)
        cause.save()
        causes_list.append({"attribute": attribute, "attribute_id": attribute_id, "value": str(session.path), "prob": prob})
        anomaly.causes.add(cause)

    time_to_diagnose = time.time() - cur_timestamp
    anomaly.timeToDiagnose = time_to_diagnose
    anomaly.save()
    user.anomalies.add(anomaly)
    user.save()

    diagRst['causes'] = causes_list
    diagRst['duration'] = time_to_diagnose

    return diagRst