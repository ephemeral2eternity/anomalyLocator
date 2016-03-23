from django.db import models
from django.utils import timezone

# Create your models here.
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
	route = models.CharField(max_length=5000)
	latest_update = models.DateTimeField(auto_now=True)
	
	def __str__(self):
		return str(self.name)

class Node(models.Model):
	name = models.CharField(max_length=100, default="")
	ip = models.CharField(max_length=100)
	city = models.CharField(max_length=100, default="")
	region = models.CharField(max_length=100, default="")
	country = models.CharField(max_length=100, default="")
	AS = models.CharField(max_length=100, default="")
	ISP = models.CharField(max_length=200, default="")
	longitude = models.DecimalField(max_digits=10, decimal_places=5, default=0.0)
	latitude = models.DecimalField(max_digits=10, decimal_places=5, default=0.0)
	clients = models.CharField(max_length=5000, default="")
	nodeType = models.CharField(max_length=10, default="router")
	latest_check = models.DateTimeField(auto_now=True)

	def __str__(self):
		return str(self.name)

class Edge(models.Model):
	src = models.CharField(max_length=100, default="")
	srcIP = models.CharField(max_length=100, default="")
	dst = models.CharField(max_length=100, default="")
	dstIP = models.CharField(max_length=100, default="")
	latest_check = models.DateTimeField(auto_now=True)
	def __str__(self):
		return str(self.srcIP + "---" + self.dstIP)

class Anomaly(models.Model):
	client=models.CharField(max_length=100)
	server=models.CharField(max_length=100)
	normal=models.CharField(max_length=5000)
	abnormal=models.CharField(max_length=5000)
	peers = models.CharField(max_length=5000)
	timestamp = models.DateTimeField(auto_now_add=True)
	def __str__(self):
		return str(self.client)
