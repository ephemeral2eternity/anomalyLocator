from django.db import models

# Monitor the event for each client.
class Event(models.Model):
    type = models.CharField(max_length=1000)
    prevVal = models.CharField(max_length=100)
    curVal = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str("[ Event: " + self.type + "]" +self.prevVal + " ---> " + str(self.curVal))

    class Meta:
        ordering = ('timestamp', )

# Monitor the updates from each client.
class Update(models.Model):
    client_ip = models.CharField(max_length=100)
    server_ip = models.CharField(max_length=100)
    qoe = models.DecimalField(max_digits=5, decimal_places=4)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{client: " + self.client_ip + ", Server: " + self.server_ip + ", QoE: " + str(self.qoe) + ", time:" + str(self.timestamp) + "}"

    class Meta:
        ordering = ('timestamp', )

# Node class defines a node that is either a router, or a client , or a server
class Node(models.Model):
    name = models.CharField(max_length=100)
    ip = models.CharField(max_length=100)
    type = models.CharField(max_length=100)
    network_id = models.IntegerField(default=-1)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.type + ":" + self.ip

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

    def __str__(self):
        return "Network " + str(self.id) + " AS " + str(self.ASNumber) + " at (" + str(self.latitude) + ", " + str(self.longitude) + ")"

    class Meta:
        index_together = ["ASNumber", "latitude", "longitude"]
        unique_together = ("ASNumber", "latitude", "longitude")

class DeviceInfo(models.Model):
    device = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    player = models.CharField(max_length=100)
    browser = models.CharField(max_length=100)
    updates = models.ManyToManyField(Update, blank=True)

    def __str__(self):
        return "(" + self.device + ", " + self.os + ", " + self.player + ", " + self.browser + ")"

class Server(models.Model):
    name = models.CharField(max_length=100)
    ip = models.CharField(max_length=100)
    network_id = models.IntegerField(default=-1)
    updates = models.ManyToManyField(Update, blank=True)

    def __str__(self):
        return "Server: " + self.ip + "(" + self.name + ")"

# Client class defines all events, server, route and path for a client's video session
class Client(models.Model):
    name = models.CharField(max_length=100)
    ip = models.CharField(max_length=100)
    network_id = models.IntegerField(default=-1)
    device = models.ForeignKey(DeviceInfo, default=None)
    server = models.ForeignKey(Server, default=None)
    events = models.ManyToManyField(Event, blank=True)
    route = models.ManyToManyField(Node, through='Hop')
    route_networks = models.ManyToManyField(Network, blank=True)
    pathLen = models.IntegerField(default=-1)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name + "connecting to " + self.server

# Define hop with its sequence on a client's route
class Hop(models.Model):
    node = models.ForeignKey(Node, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    hopID = models.PositiveIntegerField()

    def __str__(self):
        return self.client.name + ": " + str(self.hopID) + ", " + self.node.name


class Edge(models.Model):
    src = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_source')
    dst = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_target')
    latest_check = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ["src", "dst"]

    def __str__(self):
        return str(self.src.ip + "---" + self.dst.ip)

class Anomaly(models.Model):
    type = models.CharField(max_length=100)
    client = models.CharField(max_length=100)
    server = models.CharField(max_length=100)
    qoe = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    suspect_networks = models.ManyToManyField(Network)
    suspect_deviceInfo = models.ForeignKey(DeviceInfo, blank=True, null=True)
    suspect_server = models.ForeignKey(Server, blank=True, null=True)
    suspect_server = models.ForeignKey(Server, blank=True, null=True)
    suspect_events = models.ManyToManyField(Event)
    suspect_path_length = models.IntegerField(default=-1)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.type + " QoE anomaly"

class Cause(models.Model):
    descr = models.CharField(max_length=200)
    occurance = models.IntegerField(default=0)

    def __str__(self):
        return self.descr

class Diagnosis(models.Model):
    id = models.IntegerField(primary_key=True)
    causes = models.ManyToManyField(Cause)
    total = models.IntegerField()
    timeToDiagnose = models.DecimalField(max_digits=10, decimal_places=5)
    timestamp = models.DateTimeField(auto_now_add=True)