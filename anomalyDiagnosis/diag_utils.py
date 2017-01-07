## diag_utils.py
# By Chen Wang, Jan 3, 2017
import datetime
import time
import socket
from anomalyDiagnosis.models import Node, Server, DeviceInfo, User, Session, Event, Anomaly, Status, Path
from anomalyDiagnosis.thresholds import *

def get_exp_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 0))
    return s.getsockname()[0]

def update_attributes(client_ip, server_ip, update):
    isUpdated = False

    try:
        user = User.objects.get(ip=client_ip)
        if user.device:
            user.device.updates.add(update)
            user.device.save()

        if user.server:
            user.server.updates.add(update)
            user.server.save()
        user.save()

        user_updated = True
        print("Successfully update user with " + client_ip)
    except:
        user_updated = False
        print("Cannot obtain user with ip: " + client_ip)

    try:
        session = Session.objects.get(client_ip=client_ip, server_ip=server_ip)
        for network in session.sub_networks.all():
            network.updates.add(update)
            network.save()

        session.save()
        session_updated = True
        print("Successfully send update for session: "+ client_ip + "<--->" + server_ip)
    except:
        session_updated = False
        print("Failed to send update for session: " + client_ip + "<--->" + server_ip)

    return (user_updated and session_updated)

def add_event(client_ip, event_dict):
    try:
        user = User.objects.get(ip=client_ip)
        event = Event(user_id=user.id, type=event_dict['type'], prevVal=event_dict['prevVal'], curVal=event_dict['curVal'])
        event.save()
        user.events.add(event)

        if str(event_dict['type']).startswith("SRV"):
            try:
                srv = Server.objects.get(ip=event_dict['curVal'])
            except:
                srv = Server(ip=event_dict['curVal'])
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
        print("Failed to add the client: %s with event %s!" % (client_ip, event_dict['type']))

    return isAdded

def check_status(updates):
    if updates.count() == 0:
        return 1
    else:
        poor_update_cnt = 0
        for update in updates.all():
            if not update.satisfied:
                poor_update_cnt += 1
        health = float(poor_update_cnt) / updates.count()
        return health

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


def diagnose(client_ip, server_ip, qoe, anomalyTyp):
    diagRst = {}
    try:
        user = User.objects.get(ip=client_ip)
    except:
        diagRst['error'] = "No user with " + client_ip + " in database!"
        return diagRst

    try:
        session = Session.objects.get(client_ip=client_ip, server_ip=server_ip)
    except:
        diagRst['error'] = "No session " + client_ip + "<--->" + server_ip + " in database!"
        return diagRst

    anomaly = Anomaly(user_id=user.id, session_id=session.id, qoe=qoe, type=anomalyTyp)
    anomaly.save()

    element_status = {}
    # cur_time = time.time()
    # cur_time = time.mktime(datetime.datetime.utcnow().timetuple())
    cur_time = datetime.datetime.now()
    cur_timestamp = cur_time.timestamp()

    ## Check device health status
    device_time_window_start = cur_time - datetime.timedelta(minutes=device_time_window)
    device_health = check_status(user.device.updates.filter(timestamp__range=(device_time_window_start, cur_time)))
    device_health_status = Status(component_id="device_" + str(user.device.id), health=device_health)
    device_health_status.save()
    element_status["device_" + str(user.device.id)] = device_health
    anomaly.element_health.add(device_health_status)

    ## Check network health status
    network_time_window_start = cur_time - datetime.timedelta(minutes=network_time_window)
    for network in session.sub_networks.all():
        network_health = check_status(network.updates.filter(timestamp__range=(network_time_window_start, cur_time)))
        network_health_status = Status(component_id="network_" + str(network.id), health=network_health)
        network_health_status.save()
        element_status["network_" + str(network.id)] = network_health
        anomaly.element_health.add(network_health_status)

    ## Check server health status
    server_time_window_start = cur_time - datetime.timedelta(minutes=server_time_window)
    server_health = check_status(user.server.updates.filter(timestamp__range=(server_time_window_start, cur_time)))
    server_health_status = Status(component_id="server_" + str(user.server.id), health=server_health)
    server_health_status.save()
    element_status["server_" + str(user.server.id)] = server_health
    anomaly.element_health.add(server_health_status)

    ## Check event proximity
    event_time_window_start = cur_time - datetime.timedelta(minutes=event_time_window)
    for event in user.events.filter(timestamp__range=(event_time_window_start, cur_time)).all():
        proximity = 1 - (cur_timestamp - event.timestamp.timestamp())/float(event_time_window*60)
        element_status["event_" + str(event.id)] = proximity
        event_proximity_status = Status(component_id="event_" + str(event.id), health=proximity)
        event_proximity_status.save()
        anomaly.element_health.add(event_proximity_status)

    long_path = check_path_length(session.path.length, cur_time)
    element_status["path_" + str(session.path.length)] = long_path
    long_path_status = Status(component_id="path_" + str(session.path.length), health=long_path)
    long_path_status.save()
    anomaly.element_health.add(long_path_status)

    time_to_diagnose = time.time() - cur_timestamp
    anomaly.timeToDiagnose = time_to_diagnose
    anomaly.save()
    user.anomalies.add(anomaly)
    user.save()
    diagRst['causes'] = element_status
    diagRst['duration'] = time_to_diagnose
    return diagRst