## threasholds.py

## Session active threshold
session_active_window = 300 # 5minutes

# Define the time window to
node_time_window = 1     # 1 minutes
network_time_window = 10    # 5 minutes
device_time_window = 60    # 1 hour

# Define the time window for an event to be suspectable
event_time_window = 60      # 60 minutes = 1 hour

# Define the time window for an event to be suspectable
path_time_window = 24       ## 1 day

## define satisfied QoE value
satisfied_qoe = 2

## show updates in this window
update_graph_window = 60        # 30 minutes before and after the anomaly

## Weighted average probability
alpha = 0.1
