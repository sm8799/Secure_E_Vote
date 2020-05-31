from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, Http404
from django.db.models import Max
from django.views.generic import (DetailView, ListView, TemplateView)
from django.views.generic.edit import (CreateView, DeleteView, UpdateView)
from sevapp.models import Admin, Entry, Election, Poff, Candidate, Voter
from .forms import AdminForm, EntryForm, LoginForm, ElectionForm, PoffForm, CandidateForm, VoterForm
from django.urls import reverse_lazy
import hashlib, binascii, os, random
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from PIL import Image, ImageDraw, ImageFont
from django.core.files import File 
import datetime, time
from socket import *
from shamir import *
from django.http import FileResponse
import io
import threading
from _thread import *
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph
from reportlab.platypus.tables import TableStyle
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet

s = socket(AF_INET, SOCK_DGRAM)
port = '8080/'
try:
	s.connect(('8.8.8.8', 8001))
	IP = s.getsockname()[0]
except:
	IP = '127.0.0.1'
s.close()
vice_url = "http://" + 	'192.168.122.1' + ":" + port + 'secureevote/'

encode_decode_dict = {'a': '011000', 'b': '000010', 'c': '101101', 'd': '011010', 'e': '101111', 'f': '110100',
'g': '010110', 'h': '000100', 'i': '001111', 'j': '110110', 'k': '000111', 'l': '110010',
'm': '100000', 'n': '100001', 'o': '011011', 'p': '011001', 'q': '111010', 'r': '101011',
's': '101001', 't': '110001', 'u': '110000', 'v': '000110', 'w': '010010', 'x': '101100',
'y': '110111', 'z': '111110', 'A': '010100', 'B': '001011', 'C': '001101', 'D': '101110',
'E': '000101', 'F': '101000', 'G': '011110', 'H': '011111', 'I': '100101', 'J': '111101',
'K': '011101', 'L': '111111', 'M': '100111', 'N': '010111', 'O': '001100', 'P': '110101',
'Q': '011100', 'R': '001010', 'S': '111001', 'T': '110011', 'U': '010011', 'V': '000011',
'W': '000001', 'X': '100010', 'Y': '100011', 'Z': '010000', '0': '000000', '1': '100100',
'2': '100110', '3': '111100', '4': '010001', '5': '111011', '6': '111000', '7': '010101',
'8': '101010', '9': '001000', ' ': '001110', '$': '001001'}

loglist = []

def hash_password(password):
	"""Hash a password for storing."""
	salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
	pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
	                            salt, 100000)
	pwdhash = binascii.hexlify(pwdhash)
	return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
	"""Verify a stored password against one provided by user"""
	salt = stored_password[:64]
	stored_password = stored_password[64:]
	pwdhash = hashlib.pbkdf2_hmac('sha512', 
	                              provided_password.encode('utf-8'), 
	                              salt.encode('ascii'), 
	                              100000)
	pwdhash = binascii.hexlify(pwdhash).decode('ascii')
	return pwdhash == stored_password

def logout(request, pk):
	if str(pk) in request.session:
		del request.session[str(pk)]
		return redirect('login')
	return redirect('home')

class BaseView(TemplateView):
	template_name = 'base.html'

class TechnologyView(TemplateView):
	template_name = 'technology.html'

class AboutView(TemplateView):
	template_name = 'about.html'

class FaqView(TemplateView):
	template_name = 'faq.html'

def admin_register(request):
	registered = False
	if request.method == 'POST':
		admin_form = AdminForm(request.POST)
		entry_form = EntryForm(request.POST)
		if admin_form.is_valid() and entry_form.is_valid():
			entry = entry_form.save()
			admin = admin_form.save(commit=False)
			mail = admin_form.cleaned_data['Email']
			admin.user = entry
			admin.save()
			obj = Admin.objects.get(Email = mail)
			cleaned_data = admin_form.cleaned_data['password']
			password = hash_password(cleaned_data)
			obj.password = password
			obj.save()
			registered = True
		else:
			print(admin_form.errors, entry_form.errors)
	else:
		admin_form = AdminForm()
		entry_form = EntryForm()
	context = {'registered':registered, 'admin_form':admin_form, 'entry_form':entry_form}
	return render(request, 'sevapp/admin_form.html', context)

def admin_login(request):
	login = False
	flag = False
	if request.method == 'POST':
		login_form = LoginForm(request.POST)
		choice = request.POST.get('choice')
		password = request.POST.get('password')
		password1 = request.POST.get('password1')
		aadhaar = request.POST.get('Aadhaar_Number')
		Email = request.POST.get('Email')
		if choice == '1':
			try:
				obj1 = Admin.objects.get(user_id = aadhaar)
				obj2 = Admin.objects.get(Email = Email)
				flag = verify_password(obj2.password, password)
				request.session[str(aadhaar)] = obj1.user_id
			except:
				flag = False
		elif choice == '3' and password == password1:
			try:
				obj1 = Poff.objects.get(user_id = aadhaar)
				obj2 = Poff.objects.get(Email = Email)
				if len(obj2.password) == 0:
					password = hash_password(password)
					obj2.password = password
					obj2.save()
					flag = True
					request.session[str(aadhaar)] = obj1.user_id
				else:
					flag = verify_password(obj2.password, password)
			except:
				flag == False
		if (flag == False):
			login = False
		else:
			login = True
			request.session[str(aadhaar)] = obj1.user_id
	else:
		login_form = LoginForm()
		flag = True
	context = {'flag': flag, 'login': login, 'login_form':login_form }
	if login == False :
		return render(request, 'sevapp/admin_login.html', context)
	elif (login == True and choice == '1'):
		context = {'name': obj2.user, 'key': obj2.Hash_key, 'email': obj2.Email, 'id':obj2.user_id}
		return redirect('admin_process', pk=obj2.user_id)
	elif (login == True and choice == '3'):
		context = {'name': obj2.user, 'key': obj2.Hash_key, 'email': obj2.Email, 'id':obj2.user_id}
		return redirect('poff_process', pk=obj2.user_id)

def admin_process(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	admin = Admin.objects.get(user_id = pk)
	context = {'name': admin.user, 'key': admin.Hash_key, 'email': admin.Email, 'id':admin.user_id}
	return render(request, 'sevapp/admin_process.html', context)

def poff_process(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	poff = Poff.objects.get(user_id = pk)
	context = {'name': poff.user, 'key': poff.Hash_key, 'email': poff.Email, 'id':poff.user_id}
	return render(request, 'sevapp/poff_process.html', context)

def create_election(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login') 
	election = False
	success = False
	if pk:
		admin = Admin.objects.get(user_id = pk)
	if request.method == "POST":
		election_form = ElectionForm(request.POST)
		if election_form.is_valid():
			obj = election_form.save(commit=False)
			obj.admin = admin
			obj.start_date = request.POST.get('start_date')
			obj.end_date = request.POST.get('end_date')
			try:
				obj.save()
				election = True
			except:
				success = True
		else:
			print(election_form.errors)
	else:
		election_form = ElectionForm()
	context = {'admin': admin, 'election': election, 'election_form': election_form, 'success': success}
	if success:
		return redirect('admin_process', pk=admin.user_id)
	return render(request, 'sevapp/election.html', context)

def poff_register(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	registered = False
	if pk:
		admin = Admin.objects.get(user_id = pk)
	if request.method == 'POST':
		poff_form = PoffForm(request.POST)
		entry_form = EntryForm(request.POST)
		if poff_form.is_valid() and entry_form.is_valid():
			entry = entry_form.save()
			poff = poff_form.save(commit=False)
			mail = poff_form.cleaned_data['Email']
			election = request.POST.get('chbox')
			poff.user = entry
			poff.save()
			obj = Poff.objects.get(Email = mail)
			obj.election = Election.objects.get(election_name = election)
			obj.save()
			registered = True
		else:
			print(poff_form.errors, entry_form.errors)
	else:
		poff_form = PoffForm()
		entry_form = EntryForm()
	context = {'registered':registered, 'poff_form':poff_form, 'entry_form':entry_form, 'admin':admin, 'id':admin.user_id }
	return render(request, 'sevapp/poff_form.html', context)

def candidate_register(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	registered = False
	if pk:
		admin = Poff.objects.get(user_id = pk)
	if request.method == 'POST':
		candidate_form = CandidateForm(request.POST, request.FILES)
		if candidate_form.is_valid():
			name = request.POST.get('name')
			aadhaar = request.POST.get('Aadhaar_Number')
			election = request.POST.get('election')
			try:
				candidate = Entry.objects.get(Aadhaar_Number = aadhaar)
				registered = False
			except:
				candidate = Candidate()
				user = Entry()
				user.Aadhaar_Number = aadhaar
				user.name = name
				user.save()
				candidate.user = user
				candidate.election = Election.objects.get(election_name = election)
				candidate.profile_pic = request.FILES.get('profile_pic')
				candidate.save()
				registered = True
		else:
			print(candidate_form.errors)
	else:
		candidate_form = CandidateForm()
	context = {'registered':registered, 'candidate_form':candidate_form, 'admin':admin}
	return render(request, 'sevapp/candidate_form.html', context)

def validate(request, slug):
	valid = True
	error = False
	voted = False
	verified = False
	if request.method == 'POST':
		aadhar = request.POST.get('aadhar')
		try:
			voter = Voter.objects.get(user_id = aadhar)
			if voter.election.start_date > datetime.date.today() or voter.election.end_date < datetime.date.today():
				ongoing = 0
				context = {'ongoing': ongoing, 'start': voter.election.start_date, 'end': voter.election.end_date}
				return render(request, 'sevapp/voter_verify.html', context)
		except:
			valid = False
			error = True
			verified = False
			context = {'valid': valid, 'error':error, 'voted':voted, 'verified':verified }
			return render(request, 'sevapp/voter_verify.html', context)
		if voter.share != '':
			voted = True
			valid = False
			verified = False
			context = {'valid': valid, 'error':error, 'voted':voted, 'verified':verified }
			return render(request, 'sevapp/voter_verify.html', context)
		else:
			request.session[str(aadhar)] = aadhar
			return redirect('vote1', slug = slug)
	else:
		valid = False
		error = False
		verified = False
	context = {'valid': valid, 'error':error, 'voted':voted, 'verified':verified }
	return render(request, 'sevapp/voter_verify.html', context)

def Mail(sub, msg, email):
	send_mail(
	    sub,
	    msg,
	    'secureevote@gmail.com',
	    [str(email)],
	    fail_silently=False,
	)

def voter_register(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	registered = False
	if str(pk) not in request.session:
		return redirect('login')
	if pk:
		admin = Poff.objects.get(user_id = pk)
	if request.method == 'POST':
		voter_form = VoterForm(request.POST)
		if voter_form.is_valid():
			name = request.POST.get('name')
			aadhaar = request.POST.get('Aadhaar_Number')
			email = request.POST.get('Email')
			chbox = request.POST.get('chbox')
			try:
				voter = Voter.objects.get(user_id = aadhaar)
				registered = False
			except:
				voter = voter_form.save(commit=False)
				user = Entry()
				user.Aadhaar_Number = aadhaar
				user.name = name
				user.save()
				voter.user = user
				string = name + str(email) + str(aadhaar) + str(random.randint(0, 300))
				password = hash_password(string)
				voter.password = password
				msg = 'Link to Cast Your Vote ' + vice_url +str(password)
				voter.save()
				voter = Voter.objects.get(Email = email)
				voter.election = Election.objects.get(election_name = chbox)
				voter.save()
				registered = True
				# send_mail(
				#     'Cast Your Vote',
				#     msg,
				#     'secureevote@gmail.com',
				#     [str(email)],
				#     fail_silently=False,
				# )
				start_new_thread(Mail, ('Cast Your Vote', msg, email))
		else:
			print(voter_form.errors)
	else:
		voter_form = VoterForm()
	context = {'registered':registered, 'voter_form':voter_form, 'id': pk, 'admin':admin}
	return render(request, 'sevapp/voter_form.html', context)

MAIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEDIA_DIR = os.path.join(MAIN_DIR, 'media/module/')
STATIC_DIR = os.path.join(MAIN_DIR, 'sevapp/static')
BALLOT = MEDIA_DIR + 'ballot.jpg'
FONT = MEDIA_DIR + 'arial.ttf'
NOTA = MEDIA_DIR + 'NOTA.jpg'
ballot = Image.open(BALLOT)
fnt = ImageFont.truetype(FONT, 20)
nota = Image.open(NOTA)
nota = nota.resize((100,124))
ballot_text = ImageDraw.Draw(ballot)
CP_X = 50
CT_X = 300
CP_Y = [126, 270, 413, 557, 700,845]
CT_Y = [188, 332, 476, 620, 764, 908] 

def ballotproduction(election):
	filepath = STATIC_DIR +'/image/final_'+ election.election_name +'.jpg'
	check = os.path.isfile(filepath)
	if check:
		return filepath
	else:
		objects = Candidate.objects.all().filter(election=election)
		total = len(objects)
		p_y = CP_Y[total]
		t_y = CT_Y[total]
		ballot.paste(nota, (CP_X, p_y))
		ballot_text.text((CT_X, t_y),"None of the Above",(0, 0, 0), font = fnt)
		j = 0
		for i in objects:
			img = Image.open(i.profile_pic)
			img = img.resize((100,124))
			ballot.paste(img, (CP_X, CP_Y[j]))
			ballot_text.text((CT_X, CT_Y[j]), str(i.user) ,(0, 0, 0), font = fnt)
			j = j + 1
		ballot.save(filepath)
		return filepath

def threshold(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	if pk:
		try:
			admin = Admin.objects.get(user_id = pk)
		except:
			return redirect('login')
		if admin.Hash_key != '':
			admin.Hash_key = ''
			admin.save()
			return redirect('admin_process', pk=pk)
		obj = Election.objects.get(admin = admin)
		a = obj.end_date
		b = datetime.datetime(a.year, a.month, a.day)
		c = datetime.datetime.now()
		a = b - c
		if a.days < 0 or (a.seconds / 60) < 1440:
			objects = Poff.objects.all().filter(election = obj)
			count = len(objects)
			secret , shares = make_random_shares(count, count)
			admin.Hash_key = str(secret)
			admin.save()
			l = zip(objects, shares)
			for i, j in l:
				msg = 'Your id : ' + str(j[0]) + '\n' + 'Your Key : ' + str(j[1])
				# send_mail(
				#     'Your Hash Key',
				#     msg,
				#     'secureevote@gmail.com',
				#     [str(i.Email)],
				#     fail_silently=False,
				# )
				start_new_thread(Mail, ('Your Hash Key', msg, i.Email))
				i.Hash_key = ''
				i.save()
	return redirect('admin_process', pk=pk)


def stegano(filepath, string, obj):
	bin_str = ''
	for i in string:
		bin_str = bin_str + encode_decode_dict[i]
	bin_str = bin_str + encode_decode_dict['$']
	l = len(bin_str)
	img = Image.open(filepath)
	data = img.getdata()
	j = 0
	data = list(data)
	for i in data:
		bin3 = '{0:08b}'.format(i[2])
		bin3 = list(bin3)
		bin3[-1] = bin_str[j]
		bin3 = ''.join(bin3)
		data[j] = (i[0], i[1], int(bin3, 2))
		j = j + 1
		if(l == j):
			break
	newimg = img.copy()
	w = img.size[0]
	x, y = 0, 0
	for i in data:
		newimg.putpixel((x, y), i)
		if(x == w - 1):
			x = 0
			y = y + 1
		else:
			x = x + 1
	name = '/image/ballot_'+ str(obj.user_id) + '.png'
	newimg.save(STATIC_DIR +  name)
	return name

notavote = 0

def two_of_one(path, obj):
	oi = Image.open(path)
	os.remove(path)
	w, h = oi.size
	ri = Image.new('RGB', (oi.size[0], oi.size[1]))
	si = Image.new('RGB', (oi.size[0], oi.size[1]))
	draw_ri = ImageDraw.Draw(ri)
	draw_si = ImageDraw.Draw(si)
	for i in range(w):
		for j in range(h):
			oi_pixel = oi.getpixel((i,j))
			ri_pixel = (random.randint(0,255), random.randint(0,255), random.randint(0,255))
			si_pixel = (oi_pixel[0] ^ ri_pixel[0], oi_pixel[1] ^ ri_pixel[1], oi_pixel[2] ^ ri_pixel[2])
			draw_ri.point((i, j), ri_pixel)
			draw_si.point((i, j), si_pixel)
	ri.save(path)
	reopen = open(path, "rb")
	django_file = File(reopen)
	os.remove(path)
	si.save(path)
	obj.share.save(os.path.basename(path), django_file, save=True)
	obj.save()

def download(request, pk):
	obj = Voter.objects.get(user_id=pk)
	path = obj.share.url
	file_path = MAIN_DIR + path
	if os.path.exists(file_path):
		with open(file_path, 'rb') as fh:
			response = HttpResponse(fh.read(), content_type="image/png")
			response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
			return response
	raise Http404

def one_of_two(file_path, path):
    ri = Image.open(file_path)
    si = Image.open(path)
    w, h = ri.size
    oi = Image.new('RGB', (w, h))
    draw_oi = ImageDraw.Draw(oi)
    for i in range(w):
        for j in range(h):
            ri_pixel = ri.getpixel((i,j))
            si_pixel = si.getpixel((i,j))
            oi_pixel = (si_pixel[0] ^ ri_pixel[0], si_pixel[1] ^ ri_pixel[1], si_pixel[2] ^ ri_pixel[2])
            draw_oi.point((i, j), oi_pixel)
    oi.save(path)
    return path

def destegano(path):
	key_list = list(encode_decode_dict.keys())
	value_list = list(encode_decode_dict.values())
	img = Image.open(path)
	data = img.getdata()
	text = ''
	bin_str = ''
	for i in data:	
		bin_str = bin_str + (list('{0:08b}'.format(i[2])))[-1]
		if len(bin_str) == 6 and bin_str != '001001':
			if bin_str in value_list:
				index = value_list.index(bin_str)
				text = text + key_list[index]
			bin_str = ''
		elif(bin_str == '001001'):
			break
	return text[0:12]

def test(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('home')
	valid = True
	error = False
	voted = False
	obj = Voter.objects.get(user_id=pk)
	path = obj.share.url
	file_path = MAIN_DIR + path
	name = '/image/ballot_'+ str(obj.user_id) + '.png'
	path = STATIC_DIR +  name
	if (os.path.exists(file_path) and os.path.exists(path)):
		path = one_of_two(file_path, path)
		try:
			aadhaar = int(destegano(path))
			if aadhaar == obj.user_id:
				verified = True
				if str(pk) in request.session:
					del request.session[str(pk)]
					os.remove(path)
				context = {'valid': valid, 'error':error, 'voted':voted, 'verified':verified }
				return render(request, 'sevapp/voter_verify.html', context)
			else:
				verified = False
				context = {'valid': valid, 'error':error, 'voted':voted, 'verified':verified }
				return render(request, 'sevapp/voter_verify.html', context)
		except:
			verified = False
			voted = True
			context = {'valid': valid, 'error':error, 'voted':voted, 'verified':verified }
			return render(request, 'sevapp/voter_verify.html', context)

def vote(request, slug):
	state = 'ongoing'
	flag = False
	filepath = ''
	today = datetime.date.today()
	if request.method == 'GET':
		objects = Voter.objects.all()
		if len(objects) == 0:
			flag = False
		for i in objects:
			if i.password == slug:
				flag = True
				if i.election.start_date <= today and i.election.end_date >= today:
					state = 'ongoing'
				elif i.election.start_date > today:
					state = 'incoming'
				else:
					state = 'outgoing'
				candidates = Candidate.objects.all().filter(election=i.election)
				extra = 5 - len(candidates)
				l = []
				while extra != 0:
					l.append('1')
					extra -= 1 
				filepath = ballotproduction(i.election)
				filepath = stegano(filepath, str(i.user_id) + str(i.user), i)
				flag = True
				break
			else:
				flag = False
		context = {'state': state, 'flag': flag, 'filepath': filepath, 'obj': i, 'candidates':candidates, 'maked':l}
		return render(request, 'sevapp/voter.html', context)
	elif request.method == 'POST' and request.POST:
		vote = request.POST.get('vote')
		if vote is not 'NOTA':
			obj = Candidate.objects.get(user_id=vote)
			obj.votes = obj.votes + 1
			obj.save()
		else:
			voter = Voter.objects.get(user_id = pk)
			election = Election.objects.get(election_name = voter.election)
			election.nota += 1
			election.save()
		objects = Voter.objects.all()
		for i in objects:
			if i.password == slug:
				name = '/image/ballot_'+ str(i.user_id) + '.png'
				two_of_one(STATIC_DIR +  name, i)
				break
		context = {'obj':i}
		return render(request, 'sevapp/voter_final.html', context)

context1 = {}

def results(request, pk = 0):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	global context1
	try:
		obj = Admin.objects.get(user_id = pk)
		process = 'admin_process'
	except:
		obj = Poff.objects.get(user_id = pk)
		process = 'poff_process'
	if request.method == 'GET':
		if obj.Hash_key == '':
			context = {'pass':0, 'fail': 0, 'obj':obj, 'process':process}
			return render(request, 'sevapp/results.html', context)
		else:
			poffs = Poff.objects.all().filter(election = obj.election)
			admin = Admin.objects.get(election = obj.election)
			shares = []
			for i in poffs:
				if i.Hash_key == '':
					context = {'pass':1, 'fail': 1, 'obj':obj, 'process':process}
					return render(request, 'sevapp/results.html', context)
				a = [int(i.Hash_key[:1]), int(i.Hash_key[1:len(i.Hash_key)])]
				shares.append(tuple(a))
			secret = recover_secret(shares)
			if secret == int(admin.Hash_key):
				Election_name = obj.election
				election = Election.objects.get(election_name=Election_name)
				start_date = election.start_date
				end_date = election.end_date
				election = obj.election
				len3 = len(Poff.objects.all().filter(election = election))
				voter_objects = Voter.objects.all().filter(election = election)
				candidate_objects = Candidate.objects.all().filter(election = election)
				winner_votes = Candidate.objects.all().aggregate(Max('votes'))['votes__max']
				total_votes = len(Voter.objects.all())
				counted_votes = 0
				for i in candidate_objects:
					counted_votes += i.votes
					if i.votes == winner_votes:
						winner_name = i.user
				counted_votes += election.nota
				percentage = (counted_votes / total_votes) * 100 
				context1 = {
					'len1': len(voter_objects),
					'len2':len(candidate_objects), 
					'candidate_objects':candidate_objects,
					'len3': len3,
					'start_date':start_date,
					'end_date':end_date,
					'obj':obj,
					'total_votes':total_votes,
					'counted_votes':counted_votes,
					'percentage':percentage,
					'winner_votes': winner_votes,
					'winner_name': winner_name,
					'Election':Election_name, 
					'process':process,
					'nota':election.nota
				}
				return render(request, 'sevapp/results.html', context1)
			else:
				context = {'pass':0, 'fail': 1, 'obj':obj, 'process':process}
				return render(request, 'sevapp/results.html', context)
	else:
		x = request.POST.get('id')
		y = request.POST.get('key')
		l = [x,y]
		obj.Hash_key = str(x) + str(y)
		obj.save()
		return redirect('results', pk=pk)

def make_doc():
	pdf = io.BytesIO()

	doc = SimpleDocTemplate( pdf, pagesize=letter)
	styles = getSampleStyleSheet()
	styleH = styles['Heading1']

	story = []
	story.append(Paragraph('Election Details', styleH))
	data = []
	li = ['Elements', 'Description']
	data.append(li)
	li = ['Name of the Election', context1['Election']]
	data.append(li)
	li = ['Number of Voters in Election', context1['len1']]
	data.append(li)
	li = ['Number of Candidates in Election', context1['len2']]
	data.append(li)
	li = ['Number of P.Os in Election', context1['len3']]
	data.append(li)
	li = ['Election Start Date', context1['start_date']]
	data.append(li)
	li = ['Election End Date', context1['end_date']]
	data.append(li)
	li = ['Viewing Under', context1['obj'].user]
	data.append(li)
	li = ['Total votes expected ', context1['total_votes']]
	data.append(li)
	li = ['Votes counted', context1['counted_votes']]
	data.append(li)
	li = ['% voting done', context1['percentage']]
	data.append(li)
	li = ['Winner of the election', context1['winner_name']]
	data.append(li)
	li = ['Winner Votes counted', context1['winner_votes']]
	data.append(li)

	t1=Table(data, hAlign='LEFT')

	t1.setStyle(TableStyle([
	    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
	    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
	    ('ALIGN',(0, 0),(0,-1), 'LEFT'),
	    ('INNERGRID', (0, 0), (-1, -1), 0.50, colors.black),
	    ('BOX', (0,0), (-1,-1), 0.25, colors.black),
	]))

	story.append(t1)
	story.append(Paragraph('Candidates Details', styleH))
	data = []
	li = ['Candidate Name', 'Votes Obtained']
	data.append(li)
	for i in context1['candidate_objects']:
		li = []
		li.append(i.user)
		li.append(i.votes)
		data.append(li)
	li = []
	li.append('NOTA')
	li.append(context1['nota'])
	data.append(li)
	t2 = Table(data, hAlign='LEFT')

	t2.setStyle(TableStyle([
	    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
	    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
	    ('ALIGN',(0, 0),(0,-1), 'LEFT'),
	    ('INNERGRID', (0, 0), (-1, -1), 0.50, colors.black),
	    ('BOX', (0,0), (-1,-1), 0.25, colors.black),
	]))
	
	story.append(t2)
	doc.build(story)
	pdf.seek(0)

	return pdf

def downloadrep(request, pk):
	if str(pk) in request.session:
		pass
	else:
		return redirect('login')
	try:
		obj = Admin.objects.get(user_id = pk)
	except:
		obj = Poff.objects.get(user_id = pk)
	pdf = make_doc()
	return FileResponse(pdf, as_attachment=True, filename='analysis.pdf')

def ongoing(request):
	objects = Election.objects.all()
	ongoing_election = []
	voter = []
	candidate = []
	percent = []
	x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
	if x_forwarded_for:
		ip = x_forwarded_for.split(',')[0]
	else:
		ip = request.META.get('REMOTE_ADDR')
	for i in objects:
		ongoing_election.append(i)
		obj = Voter.objects.all().filter(election = i)
		len3 = len(obj)
		voter.append(len3)
		count = 0
		for j in obj:
			if j.share == '':
				count += 1
		if len3 != 0:
			percentage = (len3 - count) * 100 / len3
		else:
			percentage = 0
		percent.append(percentage)
		len3 = len(Candidate.objects.all().filter(election = i))
		candidate.append(len3)
	ongoing = zip(ongoing_election, voter, candidate, percent)
	last_synced = datetime.datetime.today()
	context = {'ongoing': ongoing, 'last_synced':last_synced}
	return render(request, 'sevapp/ongoing.html', context)