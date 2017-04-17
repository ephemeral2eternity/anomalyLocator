## diag_utils.py
# By Chen Wang, Jan 3, 2017
import datetime
import time
import socket
import requests
import json
import operator
# from multiprocessing import Process, freeze_support
from anomalyDiagnosis.models import User, Session, Status, Anomaly, Cause, Path, Network, Node, DeviceInfo, Event, Update
from anomalyDiagnosis.thresholds import *
from anomalyDiagnosis.ipinfo import *
from django.db import transaction

def get_hostname():
    return socket.gethostname()

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
    # print("Check status for session " + str(session))
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
    uniq_sessions_status = []
    # print("Locate suspect nodes for session " + str(session))
    for node in session.route.all():
        node_isGood = False
        for session in node.related_sessions.all():
            if session.id not in related_sessions_status.keys():
                related_sessions_status[session.id] = check_status(session)
                if related_sessions_status[session.id]:
                    uniq_sessions_status.append(related_sessions_status[session.id])

            if related_sessions_status[session.id]:
                if related_sessions_status[session.id].isGood:
                    node_isGood = True
                    break
        if not node_isGood:
            suspect_nodes.append(node)
    return suspect_nodes, uniq_sessions_status

def get_suspect_prob(type, obj):
    # print("Running get_suspect_prob for a suspect attribute " + type + ":" + str(obj))
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
        sessions = obj.related_sessions.all()

    active_session_num = 0
    active_sessions_status = []
    good_session_num = 0
    for session in sessions:
        # print("Get status for session: " + str(session))
        session_status = check_status(session)
        if session_status:
            active_session_num += 1
            active_sessions_status.append(session_status)
            if session_status.isGood:
                good_session_num += 1

    if active_session_num > 0:
        prob = (active_session_num - good_session_num) / float(active_session_num)
    else:
        prob = 1.0

    return prob, active_sessions_status

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
            attribute_id = node.id
            attribute_obj = node
        else:
            attribute_type = "network"
            attribute_id = node.network.id
            attribute_obj = node.network
        attribute_key = attribute_type + "_" + str(attribute_id)
        if attribute_key not in ranked_attributes.keys():
            ranked_attributes[attribute_key] = {"type": attribute_type, "id": attribute_id, "obj": attribute_obj,
                                                "value":str(attribute_obj), "suspects":[]}
        ranked_attributes[attribute_key]["suspects"].append(node)

    # print(ranked_attributes)

    for attribute_key, attribute_dict in ranked_attributes.items():
        prob, related_sessions_status = get_suspect_prob(attribute_dict["type"], attribute_dict["obj"])
        ranked_attributes[attribute_key]["prob"] = prob
        ranked_attributes[attribute_key]["related_sessions_status"] = related_sessions_status
        # print(attribute_key + ", prob:" + str(prob))

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
        # print(attribute_key + ", prob:" + str(prob))

    long_path = check_path_length(session.path.length, cur_time)
    # element_status["path_" + str(session.path.length)] = long_path
    if long_path > 0.9:
        attribute_type = "path"
        attribute_id = session.path.id
        prob = long_path
        attribute_key = attribute_type + "_" + str(attribute_id)
        ranked_attributes[attribute_key] = {"type": attribute_type, "id": attribute_id, "value": str(session.path), "prob":prob}
        # print(attribute_key + ", prob:" + str(prob))

    # print("Successfully ranked suspect nodes for anomaly on session " + str(session))
    return ranked_attributes

def save_anomaly(user, session, anomaly_ts, anomaly_qoe, anomaly_type, related_sessions_status, ranked_attributes):
    anomaly_dt = datetime.datetime.utcfromtimestamp(float(anomaly_ts))
    anomaly = Anomaly(user_id=user.id, session_id=session.id, qoe=anomaly_qoe, type=anomaly_type, timestamp=anomaly_dt)
    anomaly.save()

    # print("[Debug]Anomaly saved!")

    for session_status in related_sessions_status:
        anomaly.related_session_status.add(session_status)

    # print("Save related_session_status for " + str(anomaly.id))
    # print("[Debug]Anomaly related_session_status saved!")

    for attribute_key, attribute_dict in ranked_attributes.items():
        attribute_type = attribute_dict["type"]
        attribute_id = attribute_dict["id"]
        attribute_value = attribute_dict["value"]
        prob = attribute_dict["prob"]
        cause = Cause(type=attribute_type, obj_id=attribute_id, value=attribute_value, prob=prob, timestamp=anomaly_dt)
        cause.save()
        # print("Save cause" + str(cause) + " for anomaly" + str(anomaly.id))
        if "suspects" in attribute_dict.keys():
            for node in attribute_dict["suspects"]:
                cause.suspects.add(node)
            cause.save()
        if "related_sessions_status" in attribute_dict.keys():
            for session_status in attribute_dict["related_sessions_status"]:
                cause.related_session_status.add(session_status)
            cause.save()
        anomaly.causes.add(cause)
    anomaly.save()
    # print("[Debug]Anomaly causes saved!")

    # print("Save ranked anomaly with id: " + str(anomaly.id))
    return anomaly

def anomaly_diagnosis(session, anomaly_ts, anomaly_qoe, anomaly_type):
    # print("Running anomaly diagnosis for session: " + str(session))
    suspect_nodes, related_sessions_status = locate_suspects(session)
    # print("[Debug]Suspect nodes located!")

    try:
        user = User.objects.get(client=session.client)
        ranked_attributes = rank_suspects(user, session, suspect_nodes)
        # print("[Debug]Obtained ranked_attributes")
        anomaly = save_anomaly(user, session, anomaly_ts, anomaly_qoe, anomaly_type, related_sessions_status, ranked_attributes)

        session.anomalies.add(anomaly)
        session.save()
        # print("Anomaly with id " + str(anomaly.id) + " is diagnosed and saved!")
        return anomaly
    except:
        print(session.ip + " is not associated with any user!")
        return None

def detect_anomaly(session, recent_qoes):
    anomaly_tses = [k for k, v in recent_qoes.items() if v <= satisfied_qoe]
    anomaly_pts = len(anomaly_tses)
    total_pts = len(recent_qoes)
    if anomaly_pts > 0:
        anomaly_ratio = anomaly_pts / float(total_pts)
        if anomaly_ratio < 0.2:
            anomaly_type = "light"
        elif anomaly_ratio < 0.7:
            anomaly_type = "medium"
        else:
            anomaly_type = "severe"

        anomaly_qoe = sum(recent_qoes.values()) / float(total_pts)
        anomaly_ts = max(anomaly_tses)

        # print(anomaly_type + " anomaly detected for session " + str(session))

        session_status = Status(session_id=session.id, isGood=False)
        session_status.save()
        session.status.add(session_status)
        session.save()

        try:
            cur_time = time.time()
            anomaly = anomaly_diagnosis(session, anomaly_ts, anomaly_qoe, anomaly_type)
            duration = time.time() - cur_time

            anomaly.timeToDiagnose = duration
            anomaly.save()
        except:
            print("[Error]Failed to save anomaly for session " + str(session) + " in the database!")
    else:
        session_status = Status(session_id=session.id, isGood=True)
        session_status.save()
        session.status.add(session_status)
        session.save()

def update_attributes(client_ip, server_ip, qoes):
    try:
        session = Session.objects.get(client__ip=client_ip, server__ip=server_ip)
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

def get_ave_QoE(obj, ts_start, ts_end):
    qoes = []
    sessions = []

    if obj.get_class_name() == "session":
        sessions.append(obj)
    elif obj.get_class_name() == "device":
        for user in obj.users.all():
            for session in user.sessions.all():
                sessions.append(session)
    elif obj.get_class_name() == "user":
        for session in obj.sessions.all():
            sessions.append(session)
    else:
        for session in obj.related_sessions.all():
            sessions.append(session)

    for session in sessions:
        requested_updates = session.updates.filter(timestamp__range=(ts_start, ts_end))
        for update in requested_updates.all():
            qoes.append(update.qoe)

    total = len(qoes)

    if total != 0:
        aveQoE = float(sum(qoes))/total
    else:
        aveQoE = -1.0
    return aveQoE

### @function get_top_cause(anomaly)
#   @params:
#       anomaly : the anomaly object
#   @return: top_causes ---- a list of causes objects that is ranked as top in causing the given anomaly
def get_top_cause(anomaly):
    top_causes = []

    ## Get all causes' probability and QoE scores, ignore events right now
    causes = anomaly.causes.order_by('-prob', '-qoe_score').all()
    if causes.count() > 0:
        top_cause = causes.first()
        top_causes.append(top_cause)
        top_prob = top_cause.prob
        top_qoe_score = top_cause.qoe_score
    else:
        return []

    for cause in causes:
        if (cause != top_cause) and (cause.prob == top_prob) and (cause.qoe_score == top_qoe_score):
            top_causes.append(cause)

    return top_causes

### @function classifyAnomalyOrigins()
#   @return: anomaly_origins ---- classify the top origins for all anomalies into transit/access/cloud ISP/network, server and device
def classifyAnomalyOrigins():
    anomalies = Anomaly.objects.all()
    locator_name = get_hostname()
    anomaly_origins = {"transitISP":{}, "accessISP":{}, "cloudISP":{}, "transitNet":{}, "accessNet":{}, "cloudNet":{}, "server":{}, "device":{}}
    for anomaly in anomalies:
        top_causes = get_top_cause(anomaly)

        num_top_cause = len(top_causes)
        if anomaly.type == "persistent":
            anomaly_type = "severe"
        elif anomaly.type == "recurrent":
            anomaly_type = "medium"
        elif anomaly.type == "occasional":
            anomaly_type = "light"
        else:
            anomaly_type = anomaly.type

        if num_top_cause > 0:
            origin_count = 1 / float(num_top_cause)
            for cause in top_causes:
                origin_type = cause.type
                if origin_type == "network":
                    obj = Network.objects.get(id=cause.obj_id)
                    # print(obj.type)
                    if obj.type == "transit":
                        if obj.ASNumber not in anomaly_origins["transitISP"].keys():
                            anomaly_origins["transitISP"][obj.ASNumber] = []
                        anomaly_origins["transitISP"][obj.ASNumber].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})

                        if obj.__str__() not in anomaly_origins["transitNet"].keys():
                            anomaly_origins["transitNet"][obj.__str__()] = []
                        anomaly_origins["transitNet"][obj.__str__()].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})
                    elif obj.type == "access":
                        if obj.ASNumber not in anomaly_origins["accessISP"].keys():
                            anomaly_origins["accessISP"][obj.ASNumber] = []
                        anomaly_origins["accessISP"][obj.ASNumber].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})

                        if obj.__str__() not in anomaly_origins["accessNet"].keys():
                            anomaly_origins["accessNet"][obj.__str__()] = []
                        anomaly_origins["accessNet"][obj.__str__()].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})
                    else:
                        if obj.ASNumber not in anomaly_origins["cloudISP"].keys():
                            anomaly_origins["cloudISP"][obj.ASNumber] = []
                        anomaly_origins["cloudISP"][obj.ASNumber].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})

                        if obj.__str__() not in anomaly_origins["cloudNet"].keys():
                            anomaly_origins["cloudNet"][obj.__str__()] = []
                        anomaly_origins["cloudNet"][obj.__str__()].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})
                elif origin_type == "server":
                    obj = Node.objects.get(id=cause.obj_id)
                    if obj.ip not in anomaly_origins[origin_type].keys():
                        anomaly_origins[origin_type][obj.ip] = []
                    anomaly_origins[origin_type][obj.ip].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})
                elif origin_type == "device":
                    obj = DeviceInfo.objects.get(id=cause.obj_id)
                    if obj.__str__() not in anomaly_origins[origin_type].keys():
                        anomaly_origins[origin_type][obj.__str__()] = []
                    anomaly_origins[origin_type][obj.__str__()].append({"type": anomaly_type, "count":origin_count, "id":locator_name + ":" + str(anomaly.id)})
                else:
                    continue

    return anomaly_origins


