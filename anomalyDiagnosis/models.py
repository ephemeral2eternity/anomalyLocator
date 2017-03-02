from django.db import models

# Monitor the updates from each client.
class Update(models.Model):
    session_id = models.IntegerField()
    qoe = models.DecimalField(max_digits=5, decimal_places=4)
    satisfied = models.BooleanField()
    timestamp = models.DateTimeField()

    def __str__(self):
        return str(self.session_id) + ", " + str(self.qoe) + ", " + str(self.satisfied)

    class Meta:
        ordering = ('timestamp', )

# Node class defines a node that is either a router, or a client , or a server
class Node(models.Model):
    name = models.CharField(max_length=100)
    ip = models.CharField(max_length=100, unique=True)
    type = models.CharField(max_length=100)
    network = models.ForeignKey(Network, blank=True)
    node_qoe_score = models.DecimalField(default=5, max_digits=5, decimal_places=4)
    related_sessions = models.ManyToManyField(Session, through=Hop)
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
    network_qoe_score = models.DecimalField(default=5, max_digits=5, decimal_places=4)
    related_sessions = models.ManyToManyField(Session, through=Subnetwork)
    city = models.CharField(max_length=100, default="")
    region = models.CharField(max_length=100, default="")
    country = models.CharField(max_length=100, default="")
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.type + ", AS " + str(self.ASNumber) + ", (" + str(self.latitude) + ", " + str(
            self.longitude) + ")"

    class Meta:
        index_together = ["ASNumber", "latitude", "longitude"]
        unique_together = ("ASNumber", "latitude", "longitude")

class Path(models.Model):
    session_id = models.IntegerField()
    length = models.PositiveIntegerField()
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "( session " + str(self.session_id) + "," + str(self.length) + ")"

    class Meta:
        ordering = ('length',)

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

# Monitor the event for each client.
class Event(models.Model):
    user_id = models.IntegerField()
    type = models.CharField(max_length=1000)
    prevVal = models.CharField(max_length=100)
    curVal = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "(" + self.type + "," + self.prevVal + "," + str(self.curVal) + ")"

    class Meta:
        ordering = ('timestamp',)

class DeviceInfo(models.Model):
    device = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    player = models.CharField(max_length=100)
    browser = models.CharField(max_length=100)
    updates = models.ManyToManyField(Update, blank=True)
    device_qoe_score = models.DecimalField(default=5.0, max_digits=5, decimal_places=4)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "(" + self.device + ", " + self.os + ", " + self.player + ", " + self.browser + ")"

class Cause(models.Model):
    node = models.ForeignKey(Node, null=True)
    attribute = models.CharField(max_length=100)
    attribute_id = models.IntegerField()
    attribute_value = models.CharField(max_length=100)
    attribute_qoe_score = models.DecimalField(default=-1, max_digits=5, decimal_places=4)
    prob = models.DecimalField(decimal_places=4, max_digits=5)
    session_num = models.IntegerField(default=-1)
    related_sessions = models.CharField(max_length=100, default="")
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.component + ":" + str(self.comp_value) + ":" + str(self.health)

class Anomaly(models.Model):
    type = models.CharField(max_length=100)
    user_id = models.IntegerField()
    session_id = models.IntegerField()
    qoe = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    causes = models.ManyToManyField(Cause)
    related_sessions = models.CharField(max_length=200, default="")
    timeToDiagnose = models.DecimalField(max_digits=10, decimal_places=5, default=-1)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.type + " anomaly, " + str(self.qoe)

## Monitor the user info
class User(models.Model):
    client = models.OneToOneField(Node, related_name='client_node')
    server = models.ForeignKey(Node, related_name='server_node')
    sessions = models.ManyToManyField(Session)
    events = models.ManyToManyField(Event)
    device = models.ForeignKey(DeviceInfo)
    anomalies = models.ManyToManyField(Anomaly)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.client

class Edge(models.Model):
    src = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_source')
    dst = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_target')
    isIntra = models.BooleanField(default=False)
    latest_check = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ["src", "dst"]

    def __str__(self):
        return str(self.src.name + "---" + self.dst.name)


class NetEdge(models.Model):
    srcNet = models.ForeignKey(Network, related_name='network_source')
    dstNet = models.ForeignKey(Network, related_name='network_target')
    isIntra = models.BooleanField(default=False)

    class Meta:
        unique_together = ["srcNet", "dstNet"]

    def __str__(self):
        return str(self.srcNet) + "---" + str(self.dstNet)



# Define hop with its sequence on a client's route
class Hop(models.Model):
    node = models.ForeignKey(Node, on_delete=models.CASCADE)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    hopID = models.PositiveIntegerField()
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.hopID) + ", " + str(self.node) + ", " + str(self.session)

# Define hop with its sequence on a client's route
class Subnetwork(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    network = models.ForeignKey(Network, on_delete=models.CASCADE)
    netID = models.PositiveIntegerField()

    def __str__(self):
        return str(self.netID) + ", " + str(self.network) + ", " + str(self.session)
