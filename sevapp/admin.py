from django.contrib import admin
from sevapp.models import Admin, Entry, Election, Poff, Candidate, Voter
# Register your models here.

admin.site.register(Admin)
admin.site.register(Entry)
admin.site.register(Election)
admin.site.register(Poff)
admin.site.register(Candidate)
admin.site.register(Voter)