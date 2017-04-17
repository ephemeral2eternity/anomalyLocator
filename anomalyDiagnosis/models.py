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
    name = models.CharField(max_length=500)
    ip = models.CharField(max_length=100, unique=True)
    type = models.CharField(max_length=100)
    network = models.ForeignKey('Network', blank=True)
    # node_qoe_score = models.DecimalField(default=5, max_digits=5, decimal_places=4)
    related_sessions = models.ManyToManyField('Session')
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.type + ":" + self.ip

    def get_class_name(self):
        return "node"

    # Network defines a network that several routers in an end-to-end delivery path belongs to
class Network(models.Model):
    type = models.CharField(max_length=100)
    name = models.CharField(max_length=500, default="")
    latitude = models.DecimalField(max_digits=10, decimal_places=6, default=0.0)
    longitude = models.DecimalField(max_digits=10, decimal_places=6, default=0.0)
    ASNumber = models.IntegerField(default=-1)
    nodes = models.ManyToManyField(Node, blank=True, related_name='net_nodes')
    # network_qoe_score = models.DecimalField(default=5, max_digits=5, decimal_places=4)
    related_sessions = models.ManyToManyField('Session')
    city = models.CharField(max_length=100, default="")
    region = models.CharField(max_length=100, default="")
    country = models.CharField(max_length=100, default="")
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.ASNumber) + "," + str(self.latitude) + "," + str(
            self.longitude)

    class Meta:
        index_together = ["ASNumber", "latitude", "longitude"]
        unique_together = ("ASNumber", "latitude", "longitude")

    def get_class_name(self):
        return "network"


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
    client = models.ForeignKey(Node, related_name='client_node')
    server = models.ForeignKey(Node, related_name='server_node')
    route = models.ManyToManyField(Node, through='Hop')
    sub_networks = models.ManyToManyField(Network, through='Subnetwork')
    path = models.ForeignKey(Path, null=True)
    updates = models.ManyToManyField(Update)
    anomalies = models.ManyToManyField('Anomaly', blank=True)
    status = models.ManyToManyField('Status', blank=True)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.client.name + "<-->" + self.server.name

    def get_class_name(self):
        return "session"

    def get_light_anomalies(self):
        return Anomaly.objects.filter(type="light", session_id=self.id)

    def get_medium_anomalies(self):
        return Anomaly.objects.filter(type="medium", session_id=self.id)

    def get_severe_anomalies(self):
        return Anomaly.objects.filter(type="severe", session_id=self.id)

    def get_all_anomalies(self):
        return Anomaly.objects.filter(session_id=self.id)

    class Meta:
        index_together = ["client", "server"]
        unique_together = ["client", "server"]

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

class Status(models.Model):
    session_id = models.IntegerField()
    isGood = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.isGood:
            return str(self.session) + " is good @ " + str(self.timestamp)
        else:
            return str(self.session) + " is bad @ " + str(self.timestamp)

    class Meta:
        ordering = ['timestamp',]

class Cause(models.Model):
    type = models.CharField(max_length=100)
    obj_id = models.IntegerField()
    value = models.CharField(max_length=500)
    qoe_score = models.DecimalField(default=-1, max_digits=5, decimal_places=4)
    prob = models.DecimalField(decimal_places=4, max_digits=5)
    suspects = models.ManyToManyField(Node, blank=True)
    related_session_status = models.ManyToManyField(Status, blank=True)
    timestamp = models.DateTimeField()

    def __str__(self):
        return self.type + ":" + str(self.value) + ":" + str(self.prob)

class Anomaly(models.Model):
    type = models.CharField(max_length=100)
    user_id = models.IntegerField()
    session_id = models.IntegerField()
    qoe = models.DecimalField(max_digits=5, decimal_places=4, default=0.0)
    causes = models.ManyToManyField(Cause)
    related_session_status = models.ManyToManyField(Status, blank=True)
    timeToDiagnose = models.DecimalField(max_digits=10, decimal_places=5, default=-1)
    timestamp = models.DateTimeField()

    def __str__(self):
        return "Anomaly: " + self.type + ", " + str(self.qoe) + ", session: " + str(self.session_id)

## Monitor the user info
class User(models.Model):
    client = models.OneToOneField(Node, related_name='client')
    server = models.ForeignKey(Node, related_name='server')
    sessions = models.ManyToManyField(Session)
    events = models.ManyToManyField(Event)
    device = models.ForeignKey("DeviceInfo")
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.client.__str__()

    def get_class_name(self):
        return "user"

class DeviceInfo(models.Model):
    users = models.ManyToManyField(User, blank=True)
    device = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    player = models.CharField(max_length=100)
    browser = models.CharField(max_length=100)
    # device_qoe_score = models.DecimalField(default=5.0, max_digits=5, decimal_places=4)
    latest_check = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "(" + self.device + ", " + self.os + ", " + self.player + ", " + self.browser + ")"

    def get_class_name(self):
        return "device"

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
