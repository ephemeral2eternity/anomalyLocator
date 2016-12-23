## threasholds.py


# Define all thresholds for label_suspects and diagnosing anomalies
server_suspect_th = 60     # 5 minutes
network_suspect_th = 60    # 5 minutes
device_suspect_th = 600    # 1 hour

# Define the threshold for QoE anomaly diagnosis
diagnosis_time_window_minutes = 10

# Define the time window for an event to be suspectable
event_suspect_th = 600
