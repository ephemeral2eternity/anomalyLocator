## diag_utils.py
# By Chen Wang, Jan 3, 2017
import datetime
import time
import socket
import requests
import json
from multiprocessing import Process, freeze_support
from anomalyDiagnosis.models import Node, Network, DeviceInfo, User, Session, Event, Status, Anomaly, Cause, Path, Update
from anomalyDiagnosis.thresholds import *
from anomalyDiagnosis.ipinfo import *
from django.db import transaction

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

def check_status(session, timestamp=None):
    if timestamp is None:
        check_time = datetime.datetime.now()
    else:
        check_time = datetime.datetime.utcfromtimestamp(float(timestamp))

    # To check if the session is still active.
    latest_status = session.status.filter(timestamp__lte=check_time).latest('timestamp')
    if (check_time.timestamp() - latest_status.timestamp.timestamp() < session_active_window):
        return latest_status

    return None

def locate_suspects(session):
    suspect_nodes = []
    related_sessions_status = {}
    for node in session.route.all():
        node_isGood = False
        for session in node.related_sessions.all():
            if session.id not in related_sessions_status.keys():
                related_sessions_status[session.id] = check_status(session)
            if related_sessions_status[session.id]:
                if related_sessions_status[session.id].isGood:
                    node_isGood = True
                    break
        if not node_isGood:
            suspect_nodes.append(node)
    return suspect_nodes, related_sessions_status.values()

def get_suspect_prob(type, obj):
    if type == "device":
        users = obj.users.all()
        sessions = []
        session_ids = []
        for user in users:
            for session in user.sessions.all():
                if session.id not in session_ids:
                    session_ids.append(session.id)
                    sessions.append(session)
    else:
        sessions = obj.related_session.all()

    active_session_num = 0
    active_sessions = []
    good_session_num = 0
    for session in sessions:
        session_status, _ = check_status(session)
        if session_status:
            active_session_num += 1
            active_sessions.append(session)
            if session_status.isGood:
                good_session_num += 1

    if active_session_num > 0:
        prob = (active_session_num - good_session_num) / float(active_session_num)
    else:
        prob = 1.0

    return prob, active_sessions

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

def rank_suspects(user, session, suspect_nodes):
    ranked_attributes = {}

    for node in suspect_nodes:
        if node.type == "client":
            attribute_type = "device"
            attribute_id = user.device.id
            attribute_obj = user.device
        elif node.type == "server":
            attribute_type = "server"
            attribute_id = user.server.id
            attribute_obj = user.server
        else:
            attribute_type = "network"
            attribute_id = node.network.id
            attribute_obj = node.network
        attribute_key = attribute_type + "_" + str(attribute_id)
        if attribute_key not in ranked_attributes.keys():
            ranked_attributes[attribute_key] = {"type": attribute_type, "id": attribute_id, "obj": attribute_obj,
                                                "value":str(attribute_obj), "suspects":[]}
        ranked_attributes[attribute_key]["suspects"].append(node)

    for attribute_key, attribute_dict in ranked_attributes.items():
        prob, related_sessions = get_suspect_prob(attribute_dict["type"], attribute_dict["obj"])
        ranked_attributes[attribute_key]["prob"] = prob
        ranked_attributes[attribute_key]["related_sessions"] = related_sessions

    ## Check event proximity
    cur_time = datetime.datetime.now()
    cur_timestamp = cur_time.timestamp()
    event_time_window_start = cur_time - datetime.timedelta(minutes=event_time_window)
    for event in user.events.filter(timestamp__range=(event_time_window_start, cur_time)).all():
        prob = 1 - (cur_timestamp - event.timestamp.timestamp())/float(event_time_window*60)
        attribute_type = "event"
        attribute_id = event.id
        attribute_key = attribute_type + "_" + str(attribute_id)
        ranked_attributes[attribute_key] = {"type": attribute_type, "id": attribute_id, "value": str(event), "prob":prob}

    long_path = check_path_length(session.path.length, cur_time)
    # element_status["path_" + str(session.path.length)] = long_path
    if long_path > 0.9:
        attribute_type = "path"
        attribute_id = session.path.id
        prob = long_path
        attribute_key = attribute_type + "_" + str(attribute_id)
        ranked_attributes[attribute_key] = {"type": attribute_type, "id": attribute_id, "value": str(session.path), "prob":prob}

    return ranked_attributes

@transaction.atomic
def save_anomaly(user, session, anomaly_qoe, anomaly_type, related_sessions_status, ranked_attributes):
    anomaly = Anomaly(user_id=user.id, session_id=session.id, qoe=anomaly_qoe, type=anomaly_type)
    anomaly.save()

    for session_status in related_sessions_status:
        anomaly.related_session_status.add(session_status)

    for attribute_key, attribute_dict in ranked_attributes.items():
        attribute_type = attribute_dict["type"]
        attribute_id = attribute_dict["id"]
        attribute_value = attribute_dict["value"]
        prob = attribute_dict["prob"]
        cause = Cause(type=attribute_type, obj_id=attribute_id, value=attribute_value, prob=prob)
        if "suspects" in attribute_dict.keys():
            for node in attribute_dict["suspects"]:
                cause.suspects.add(node)
        if "related_sessions" in attribute_dict.keys():
            for session_status in attribute_dict["related_sessions"]:
                cause.related_session_status.add(session_status)
        cause.save()
        anomaly.causes.add(cause)
    anomaly.save()
    return anomaly

def fork_anomaly_diagnosis(session, anomaly_qoe, anomaly_type):
    p = Process(target=anomaly_diagnosis, args=(session, anomaly_qoe, anomaly_type))
    p.start()
    return p

def anomaly_diagnosis(session, anomaly_qoe, anomaly_type):
    suspect_nodes, related_sessions_status = locate_suspects(session)

    try:
        user = User.objects.get(client__ip=session.client_ip)
        ranked_attributes = rank_suspects(user, session, suspect_nodes)
        anomaly = save_anomaly(user, session, anomaly_qoe, anomaly_type, related_sessions_status, ranked_attributes)
        print("Anomaly with id " + str(anomaly.id) + " is diagnosed and saved!")
    except:
        print(session.ip + " is not associated with any user!")

def detect_anomaly(session, recent_qoes):
    anomaly_idx = [x for x in recent_qoes.values() if x <= satisfied_qoe]
    anomaly_pts = len(anomaly_idx)
    total_pts = len(recent_qoes)
    if anomaly_pts > 0:
        anomaly_ratio = anomaly_pts / float(total_pts)
        if anomaly_ratio < 0.2:
            anomaly_type = "occasional"
        elif anomaly_ratio < 0.7:
            anomaly_type = "recurrent"
        else:
            anomaly_type = "persistent"

        anomaly_qoe = sum(recent_qoes.values()) / float(total_pts)

        session_status = Status(session_id=session.id, isGood=False)
        session_status.save()
        session.status.add(session_status)
        session.save()

        fork_anomaly_diagnosis(session, anomaly_qoe, anomaly_type)
    else:
        session_status = Status(session_id=session.id, isGood=True)
        session_status.save()
        session.status.add(session_status)
        session.save()

@transaction.atomic
def update_attributes(client_ip, server_ip, qoes):
    try:
        session = Session.objects.get(client_ip=client_ip, server_ip=server_ip)
        for ts, qoe in qoes.items():
            dtfield = datetime.datetime.utcfromtimestamp(float(ts))
            update = Update(session_id=session.id, qoe=qoe, satisfied=(qoe >= satisfied_qoe), timestamp=dtfield)
            update.save()
            session.updates.add(update)
        session.save()
        detect_anomaly(session, qoes)
        return True
    except:
        print("Failed to send update for session: " + client_ip + "<--->" + server_ip)
        return False

@transaction.atomic
def add_event(client_ip, event_dict):
    try:
        user = User.objects.get(client__ip=client_ip)
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
        print("Failed to obtain user with ip %s to add event %s!" % (client_ip, event_dict['type']))

    return isAdded


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
    return aveQoE