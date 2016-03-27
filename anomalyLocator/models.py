from django.db import models
from django.utils import timezone

# Create your models here.
class Update(models.Model):
	client = models.CharField(max_length=100)
	server = models.CharField(max_length=100)
	qoe = models.DecimalField(max_digits=5, decimal_places=4)
	state = models.BooleanField()
	timestamp = models.DateTimeField(auto_now_add=True)
	def __str__(self):
		return str(self.client + ": " + str(self.state))

class Node(models.Model):
	name = models.CharField(max_length=100, default="")
	ip = models.CharField(max_length=100, unique=True)
	city = models.CharField(max_length=100, default="")
	region = models.CharField(max_length=100, default="")
	country = models.CharField(max_length=100, default="")
	AS = models.CharField(max_length=100, default="")
	ISP = models.CharField(max_length=200, default="")
	longitude = models.DecimalField(max_digits=10, decimal_places=5, default=0.0)
	latitude = models.DecimalField(max_digits=10, decimal_places=5, default=0.0)
	nodeType = models.CharField(max_length=10, default="router")
	updates = models.ManyToManyField(Update)
	latest_check = models.DateTimeField(auto_now=True)

	def __str__(self):
		return str(self.name)

class Client(models.Model):
	name = models.CharField(max_length=100)
	ip = models.CharField(max_length=100)
	server = models.CharField(max_length=100)
	city = models.CharField(max_length=100)
	region = models.CharField(max_length=100)
	country = models.CharField(max_length=100)
	AS = models.CharField(max_length=100)
	ISP = models.CharField(max_length=200)
	longitude = models.DecimalField(max_digits=10, decimal_places=5)
	latitude = models.DecimalField(max_digits=10, decimal_places=5)
	route = models.ManyToManyField(Node, through='Hop')
	latest_update = models.DateTimeField(auto_now=True)
	
	class Meta:
        	index_together = ["ip", "server"]
        	unique_together = ("ip", "server")
	
	def __str__(self):
		return str(self.name + ", " + self.ip + ", " + self.server + ", " + self.ISP)

class Hop(models.Model):
	node = models.ForeignKey(Node, on_delete=models.CASCADE)
	client = models.ForeignKey(Client, on_delete=models.CASCADE)
	hopID =  models.PositiveIntegerField()
	
	def __str__(self):
		return client.name + ": " + str(hopID) + ", " + node.name


class Edge(models.Model):
	src = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_source')
	dst = models.ForeignKey(Node, on_delete=models.CASCADE, related_name='node_target')
	latest_check = models.DateTimeField(auto_now=True)
	
	class Meta:
        	unique_together = ["src", "dst"]
	
	def __str__(self):
		return str(self.src.ip + "---" + self.dst.ip)

class Anomaly(models.Model):
	client=models.CharField(max_length=100)
	server=models.CharField(max_length=100)
	normal=models.CharField(max_length=5000)
	abnormal=models.CharField(max_length=5000)
	peers = models.CharField(max_length=5000)
	timeToLocate = models.DecimalField(max_digits=10, decimal_places=5)
	timestamp = models.DateTimeField(auto_now_add=True)
	def __str__(self):
		return str(self.client)
