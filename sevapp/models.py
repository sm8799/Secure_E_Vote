from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from django.urls import reverse
from django.contrib.auth.models import User

# Create your models here.

class Entry(models.Model):
	Aadhaar_Number = models.BigIntegerField(primary_key=True,validators = [MinValueValidator(100000000000), MaxValueValidator(999999999999)])
	name = models.CharField(max_length=200)
	
	def __str__(self):
		return self.name


class Admin(models.Model):
	user = models.OneToOneField(Entry, on_delete=models.CASCADE)
	Email = models.EmailField(primary_key = True,max_length=200)
	password = models.CharField(max_length=200)
	Hash_key = models.CharField(max_length=200)


	def __str__(self):
		return self.user.name

class Election(models.Model):
	admin = models.OneToOneField(Admin, on_delete=models.CASCADE)
	election_name = models.CharField(primary_key =True, max_length=200)
	start_date = models.DateField()
	end_date = models.DateField()
	nota = models.BigIntegerField(default=0)

	def __str__(self):
		return self.election_name

class Poff(models.Model):
	user = models.OneToOneField(Entry, on_delete=models.CASCADE)
	Email = models.EmailField(primary_key=True, max_length=200)
	Hash_key = models.CharField(max_length=200)
	password = models.CharField(max_length=200)
	election = models.ForeignKey(Election, on_delete=models.CASCADE, null=True)

	def __str__(self):
		return self.user.name

class Candidate(models.Model):
	user = models.OneToOneField(Entry, on_delete=models.CASCADE)
	election = models.ForeignKey(Election, on_delete=models.CASCADE)
	profile_pic = models.ImageField(upload_to = 'profile')
	votes = models.BigIntegerField(default=0)

	def __str__(self):
		return self.user.name

class Voter(models.Model):
	user = models.OneToOneField(Entry, on_delete=models.CASCADE)
	Email = models.EmailField(primary_key=True, max_length=200)
	election = models.ForeignKey(Election, on_delete=models.CASCADE, null=True)
	share = models.ImageField(upload_to = 'shares', null = True)
	password = models.CharField(max_length=200, null = True)

	def __str__(self):
		return self.user.name

