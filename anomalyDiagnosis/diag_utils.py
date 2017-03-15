## diag_utils.py
# By Chen Wang, Jan 3, 2017
import datetime
import time
import socket
import requests
import json
import operator
# from multiprocessing import Process, freeze_support
from anomalyDiagnosis.models import User, Status, Anomaly, Cause, Path, Network, Node, DeviceInfo
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

@transaction.atomic
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

# chenw-20170314
def get_top_cause(anomaly):
    top_causes = {}
    cause_prob = {}
    cause_qoe = {}

    ## Get all causes' probability and QoE scores, ignore events right now
    for cause in anomaly.causes.all():
        if cause.type == "network":
            obj = Network.objects.get(id=cause.obj_id)
            obj_key = obj.name
        elif cause.type == "server":
            obj = Node.objects.get(id=cause.obj_id)
            obj_key = obj.name
        elif cause.type == "device":
            obj = DeviceInfo.objects.get(id=cause.obj_id)
            obj_key = obj.__str__()
        else:
            continue

        if obj_key not in cause_prob.keys():
            cause_prob[obj_key] = cause.prob
            cause_qoe[obj_key] = cause.qoe_score
        elif cause_prob[obj_key] < cause.prob:
            cause_prob[obj_key] = cause.prob
            cause_qoe[obj_key] = cause.qoe_score
        else:
            continue

    sorted_cause_prob = sorted(cause_prob.items(), key=operator.itemgetter(1), reverse=True)
    max_prob = sorted_cause_prob[0][1]

    top_causes_by_prob = []
    top_causes_by_prob_qoe_scores = {}
    for item in sorted_cause_prob:
        if item[1] >= max_prob:
            top_causes_by_prob.append(item[0])
            top_causes_by_prob_qoe_scores[item[0]] = cause_qoe[item[0]]
        else:
            break

    top_causes_by_prob_and_qoe = []
    sorted_top_causes_by_prob_qoe_scores = sorted(top_causes_by_prob_qoe_scores.items(), key=operator.itemgetter(1))
    top_cause_qoe_score = sorted_top_causes_by_prob_qoe_scores[0][1]
    for item in sorted_top_causes_by_prob_qoe_scores:
        if item[1] <= top_cause_qoe_score:
            top_causes_by_prob_and_qoe.append(item[0])
        else:
            break

    if len(top_causes_by_prob_and_qoe) > 0:
        for cause_key in top_causes_by_prob_and_qoe:
            top_causes[cause_key] = 1 / float(len(top_causes_by_prob_and_qoe))

    return top_causes



