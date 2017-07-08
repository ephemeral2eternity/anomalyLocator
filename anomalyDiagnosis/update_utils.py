from anomalyDiagnosis.models import Node, ISP, Network, DeviceInfo, Session, Event, Update, Anomaly, Cause
from anomalyDiagnosis.diag_utils import *
import pytz

@transaction.atomic
def update_attributes(client_ip, server_ip, qoes):
    try:
        session = Session.objects.get(client__ip=client_ip, server__ip=server_ip)
        for ts, qoe in qoes.items():
            dtfield = datetime.datetime.utcfromtimestamp(float(ts)).replace(tzinfo=pytz.utc)
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
                    isp = ISP.objects.get(ASNumber=srv_info["AS"])
                except:
                    isp = ISP(ASNumber=srv_info["AS"], name=srv_info["ISP"], type="cloud")
                    isp.save()

                try:
                    srv_network = Network.objects.get(isp=isp, latitude=srv_info["latitude"], longitude=srv_info["longitude"])
                except:
                    srv_network = Network(isp=isp,
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

def update_origin_qoe_score(anomaly):
    anomaly_ts = anomaly.timestamp
    time_window_start = anomaly_ts - datetime.timedelta(minutes=update_graph_window)
    time_window_end = anomaly_ts + datetime.timedelta(minutes=update_graph_window)

    for cause in anomaly.causes.all():
        if cause.type == "network":
            obj = Network.objects.get(id=cause.obj_id)
        elif cause.type == "server":
            obj = Node.objects.get(id=cause.obj_id)
        elif cause.type == "device":
            obj = DeviceInfo.objects.get(id=cause.obj_id)
            # session = Session.objects.get(id=anomaly.session_id)
            # obj = session.client
        else:
            continue

        cause.qoe_score = get_ave_QoE(obj, time_window_start, time_window_end)
        cause.save()

    anomaly.save()
    return anomaly