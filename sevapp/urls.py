from django.urls import path, re_path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.BaseView.as_view(), name='home'),
    path('faq/', views.FaqView.as_view(), name='faq'),
    path('about/', views.AboutView.as_view(), name = 'about'),
    path('register/', views.admin_register, name='createadmin'),
    path('login/', views.admin_login, name= 'login'),
    path('login/admin/<pk>', views.admin_process, name='admin_process'),
    path('threshold/<int:pk>', views.threshold, name='threshold'), 
    path('add/<int:pk>', views.poff_register, name = 'addpoff'),
    path('login/poff/<pk>', views.poff_process, name='poff_process'),
    path('login/add/Voter/<int:pk>', views.voter_register, name = 'addvoter'),
    path('login/add/Candidate/<int:pk>', views.candidate_register, name = 'addcan'),
    path('create/<int:pk>', views.create_election, name = 'creele'),
    path('logout/<int:pk>', views.logout, name = 'logout'),
    path('downloadrep/<int:pk>', views.downloadrep, name = 'downloadrep'),
    path('secureevote/<slug:slug>', views.validate, name = 'vote'),
    path('secureevote/vote/<slug:slug>', views.vote, name = 'vote1'),
    re_path(r'^vote/download/(?P<pk>[0-9]+)$', views.download, name='download'),
    re_path(r'^vote/test/(?P<pk>[0-9]+)$', views.test, name='test'), 
    path('election/results/<int:pk>', views.results, name='results'),
    path('technology/', views.TechnologyView.as_view(), name='technology'),
    path('ongoing/', views.ongoing, name='ongoing'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)