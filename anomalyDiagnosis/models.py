from django.db import models

## Monitor the user info
class User(models.Model):
    ip = models.CharField(max_length=100, unique=True, primary_key=True)
    name = models.CharField(max_length=100)
    server = models.ForeignKey(Server)
    sessions = models.ManyToManyField(Session)
    events = models.ManyToManyField(Event)
    device = models.ForeignKey(DeviceInfo)
    anomalies = models.ManyToManyField(Anomaly)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.client

## Session information
class Session(models.Model):
    client_ip = models.CharField(max_length=100)
    server_ip = models.CharField(max_length=100)
    route = models.ManyToManyField(Node, through='Hop')
    sub_networks = models.ManyToManyField(Network, through='Subnetwork')
    path = models.ForeignKey(Path, null=True)
    updates = models.ManyToManyField(Update)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.client_ip + "<-->" + self.server_ip

    class Meta:
        index_together = ["client_ip", "server_ip"]
        unique_together = ["client_ip", "server_ip"]

# Node class defines a node that is either a router, or a client , or a server
class Node(models.Model):
    name = models.CharField(max_length=100)
    ip = models.CharField(max_length=100, unique=True, primary_key=True)
    type = models.CharField(max_length=100)
    network_id = models.IntegerField(default=-1)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.type + ":" + self.ip

class Edge(models.Model):
    src = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_source')
    dst = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_target')
    latest_check = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ["src", "dst"]

    def __str__(self):
        return str(self.src.name + "---" + self.dst.name)

# Network defines a network that several routers in an end-to-end delivery path belongs to
class Network(models.Model):
    type = models.CharField(max_length=100)
    name = models.CharField(max_length=100, default="")
    latitude = models.DecimalField(max_digits=10, decimal_places=4, default=0.0)
    longitude = models.DecimalField(max_digits=10, decimal_places=4, default=0.0)
    ASNumber = models.IntegerField(default=-1)
    nodes = models.ManyToManyField(Node)
    updates = models.ManyToManyField(Update, blank=True)
    city = models.CharField(max_length=100, default="")
    region = models.CharField(max_length=100, default="")
    country = models.CharField(max_length=100, default="")
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.type + ":AS " + str(self.ASNumber) + "@(" + str(self.latitude) + ", " + str(
            self.longitude) + ")"

    class Meta:
        index_together = ["ASNumber", "latitude", "longitude"]
        unique_together = ("ASNumber", "latitude", "longitude")

class NetEdge(models.Model):
    src_net = models.ForeignKey(Network)
    dst_net = models.ForeignKey(Network)

    class Meta:
        unique_together = ["src_net", "dst_net"]

    def __str__(self):
        return str(self.src_net) + "---" + str(self.dst_net)

# Monitor the event for each client.
class Event(models.Model):
    user_id = models.IntegerField()
    type = models.CharField(max_length=1000)
    prevVal = models.CharField(max_length=100)
    curVal = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.type + "," + self.prevVal + "," + str(self.curVal)

    class Meta:
        ordering = ('timestamp', )

# Monitor the updates from each client.
class Update(models.Model):
    session_id = models.IntegerField()
    qoe = models.DecimalField(max_digits=5, decimal_places=4)
    satisfied = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.session_id) + ", " + str(self.qoe) + ", " + str(self.satisfied)

    class Meta:
        ordering = ('timestamp', )

class DeviceInfo(models.Model):
    device = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    player = models.CharField(max_length=100)
    browser = models.CharField(max_length=100)
    updates = models.ManyToManyField(Update, blank=True)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.device + ", " + self.os + ", " + self.player + ", " + self.browser

class Server(models.Model):
    ip = models.CharField(max_length=100, unique=True, primary_key=True)
    updates = models.ManyToManyField(Update, blank=True)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.node)

# Define hop with its sequence on a client's route
class Hop(models.Model):
    node = models.ForeignKey(Node, on_delete=models.CASCADE)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    hopID = models.PositiveIntegerField()
    timestamp = models.DateTimeField(auto_created=True)

    def __str__(self):
        return str(self.hopID) + ", " + str(self.node) + ", " + str(self.session)

# Define hop with its sequence on a client's route
class Subnetwork(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    network = models.ForeignKey(Network, on_delete=models.CASCADE)
    netID = models.PositiveIntegerField()

    def __str__(self):
        return str(self.netID) + ", " + str(self.network) + ", " + str(self.session)

class Anomaly(models.Model):
    type = models.CharField(max_length=100)
    user_id = models.IntegerField()
    session_id = models.IntegerField()
    qoe = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    element_health = models.ManyToManyField(Status)
    timeToDiagnose = models.DecimalField(max_digits=10, decimal_places=5)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.type + " QoE anomaly"

class Status(models.Model):
    component_id = models.CharField(max_length=100)
    health = models.DecimalField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.component_id + ":" + str(self.health)

class Path(models.Model):
    session_id = models.IntegerField()
    length = models.PositiveIntegerField()
    timestamp = models.DateTimeField(auto_created=True)

    def __str__(self):
        return str(self.session_id) + "," + str(self.length)

    class Meta:
        ordering = ('length', )