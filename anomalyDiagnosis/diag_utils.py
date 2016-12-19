## diag_utils.py
# By Chen Wang, March 4, 2016
import datetime
import time
import socket
from anomalyDiagnosis.models import Client, Anomaly, Network, Server, DeviceInfo, Update, Event
from anomalyDiagnosis.thresholds import *

def get_exp_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 0))
    return s.getsockname()[0]

def update_attributes(client_ip, update):
    isUpdated = False
    try:
        client = Client.objects.get(ip=client_ip)
        client.server.updates.add(update)
        for network in client.route_networks.all():
            network.updates.add(update)
            network.save()
        client.device.updates.add(update)
        client.save()
        isUpdated = True
        print("Successfully update the client's attribute!")
    except:
        print("Failed to update the client's attribute!")

    return isUpdated

def add_event(client_ip, event_dict):
    isAdded = False
    try:
        client = Client.objects.get(ip=client_ip)
        event = Event(type=event_dict['type'], prevVal=event_dict['prevVal'], curVal=event_dict['curVal'])
        event.save()
        client.events.add(event)
        client.save()
        isAdded = True
    except:
        print("Failed to add the client: %s with event %s!" % (client_ip, event_dict['type']))

    return isAdded

def label_suspects(client_ip, server_ip, qoe, anomalyType):
    anomaly = Anomaly(type=anomalyType, client=client_ip, server=server_ip, qoe=qoe)
    curTS = time.mktime(datetime.datetime.utcnow().timetuple())
    anomaly.save()
    try:
        client = Client.objects.get(ip=client_ip)
        server = client.server
        try:
            et = client.events.latest(field_name='timestamp')
            latest_event_ts = time.mktime(et.timestamp.timetuple())
            if curTS - latest_event_ts < event_suspect_th:
                anomaly.suspect_events.add(et)
        except:
            print("No recent events that might be the cause of the anomaly!")
        anomaly.suspect_path_length = client.pathLen
        try:
            latest_server_update = server.updates.latest(field_name='timestamp')
            latest_server_update_ts = time.mktime(latest_server_update.timestamp.timetuple())

            # Label suspect server attribute to the anomaly
            if curTS - latest_server_update_ts > server_suspect_th:
                anomaly.suspect_server = server
        except:
            anomaly.suspect_server = server

        # Label suspect device attribute to the anomaly
        device = client.device
        try:
            latest_device_update_ts = time.mktime(device.updates.latest(field_name='timestamp').timestamp.timetuple())
            if curTS - latest_device_update_ts > device_suspect_th:
                anomaly.suspect_deviceInfo = device
        except:
            anomaly.suspect_deviceInfo = device

        # Label suspect network attribute to the anomaly
        for network in client.route_networks.all():
            try:
                latest_network_update_ts = time.mktime(network.updates.latest(field_name='timestamp').timestamp.timetuple())
                if curTS - latest_network_update_ts > network_suspect_th:
                    anomaly.suspect_networks.add(network)
            except:
                anomaly.suspect_networks.add(network)
    except:
        print("Cannot get the client %s object" % client_ip)

    anomaly.save()
    return anomaly

def diagnose(anomaly):
    diagRst = {}

    if anomaly.suspect_server:
        diagRst[str(anomaly.suspect_server)] = 1

    if anomaly.suspect_deviceInfo:
        diagRst[str(anomaly.suspect_deviceInfo)] = 1

    if anomaly.suspect_networks:
        for nt in anomaly.suspect_networks.all():
            diagRst[str(nt)] = 1

    if anomaly.suspect_events:
        for et in anomaly.suspect_events.all():
            diagRst[str(et)] = 1

    # diagRst["Route Length: " + str(anomaly.suspect_path_length)] = 0
    long_route_th = 12

    if (anomaly.suspect_path_length > long_route_th):
        diagRst["Route Length: " + str(anomaly.suspect_path_length)] = 1

    latest_anomaly_time = anomaly.timestamp - datetime.timedelta(milliseconds=1)
    time_window_start = latest_anomaly_time - datetime.timedelta(minutes=diagnosis_time_window_minutes)
    recent_anomalies = Anomaly.objects.filter(timestamp__range=(time_window_start, latest_anomaly_time))
    total = recent_anomalies.count() + 1
    for recent_anomaly in recent_anomalies.all():
        if anomaly.suspect_server:
            if (anomaly.suspect_server == recent_anomaly.suspect_server):
                diagRst[str(anomaly.suspect_server)] += 1
        if anomaly.suspect_deviceInfo:
            if (anomaly.suspect_deviceInfo == recent_anomaly.suspect_deviceInfo):
                diagRst[str(anomaly.suspect_deviceInfo)] += 1
        if anomaly.suspect_networks:
            for nt in anomaly.suspect_networks.all():
                if nt in recent_anomaly.suspect_networks.all():
                    diagRst[str(nt)] += 1

        if anomaly.suspect_events:
            for et in anomaly.suspect_events.all():
                if et in recent_anomaly.suspect_events.all():
                    diagRst[str(et)] += 1


    return (total, diagRst)