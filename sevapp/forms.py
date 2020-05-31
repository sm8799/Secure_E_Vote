from django import forms
from sevapp.models import Admin, Entry, Election, Poff, Candidate, Voter
from django.core.validators import MaxValueValidator, MinValueValidator


class EntryForm(forms.ModelForm):
	class Meta():
		model = Entry
		fields = ('Aadhaar_Number', 'name')
		widgets = {
			'Aadhaar_Number':forms.NumberInput(attrs = {'class':'form-control', 'placeholder':'987456321456', 'min':'100000000000'}),
			'name':forms.TextInput(attrs={'class':'form-control', 'placeholder':'secureevote'})
		}
	def clean(self):
		cleaned_data = super().clean()
		aadhar = self.cleaned_data.get('Aadhaar_Number')
		if len(str(aadhar)) != 12:
		    # Only do something if both fields are valid so far.
		    raise forms.ValidationError('invalid aadhar')

class AdminForm(forms.ModelForm):
	password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
	class Meta():
		model = Admin
		fields = ('Email',)
		widgets = {
			'Email':forms.EmailInput(attrs = {'class':'form-control', 'placeholder':'example@gmail.com'}),
		}
login_choices = (
	("1","Admin"),
	("2","Voter"),
	("3","P.O"), 
)
class LoginForm(forms.ModelForm):
	password = forms.CharField(widget=forms.PasswordInput(
		attrs = {
			'class':'form-control',
		}
	))
	Aadhaar_Number = forms.IntegerField(validators = [MinValueValidator(100000000000), MaxValueValidator(999999999999)], widget=forms.NumberInput(
		attrs = {
			'class':'form-control', 'placeholder':'987456321456','min':'100000000000', 'max':'999999999999'
		}
	))
	Email = forms.EmailField(widget=forms.EmailInput(
		attrs = {
			'class':'form-control', 'placeholder':'example@gmail.com',
		}
	))
	class Meta():
		model = Entry
		fields = ('Aadhaar_Number', )
	field_order = ['Aadhaar_Number', 'Email', 'password']

	def clean(self):
		cleaned_data = super().clean()
		aadhar = self.cleaned_data.get('Aadhaar_Number')
		if len(str(aadhar)) != 12:
		    # Only do something if both fields are valid so far.
		    raise forms.ValidationError('invalid aadhar')

class ElectionForm(forms.ModelForm):
	class Meta():
		model = Election
		fields = ('election_name',)
		widgets = {
			'election_name':forms.TextInput(attrs = {'class':'form-control', 'placeholder':'Sunitya_Pizza_Council'}),
		}

class PoffForm(forms.ModelForm):
	class Meta():
		model = Poff
		fields = ('Email',)
		widgets = {
			'Email':forms.EmailInput(attrs = {'class':'form-control', 'placeholder':'example@gmail.com'}),
		}

class CandidateForm(forms.ModelForm):
	class Meta():
		model = Candidate
		fields = ('profile_pic', 'election')
		
	name = forms.CharField(widget= forms.TextInput(
		attrs = {
			'class':'form-control'
		}
	))
	Aadhaar_Number = forms.IntegerField(validators = [MinValueValidator(100000000000), MaxValueValidator(999999999999)], widget=forms.NumberInput(
		attrs = {
			'class':'form-control', 'min':'100000000000', 'max':'999999999999', 
		}
	))
	profile_pic = forms.ImageField(widget=forms.FileInput(
		attrs={
			'class':'form-control',
			'id':'file',
		}
	))
	def clean(self):
		cleaned_data = super().clean()
		aadhar = self.cleaned_data.get('Aadhaar_Number')
		if len(str(aadhar)) != 12:
		    # Only do something if both fields are valid so far.
		    raise forms.ValidationError('invalid aadhar')

	field_order = ['name', 'Aadhaar_Number', 'election', 'profile_pic']

class VoterForm(forms.ModelForm):
	class Meta():
		model = Voter
		fields = ('Email', )
	name = forms.CharField(widget= forms.TextInput(
		attrs = {
			'class':'form-control'
		}
	))
	Aadhaar_Number = forms.IntegerField(validators = [MinValueValidator(100000000000), MaxValueValidator(999999999999)], widget=forms.NumberInput(
		attrs = {
			'class':'form-control', 'min':'100000000000', 'max':'999999999999', 
		}
	))
	Email = forms.EmailField(widget=forms.EmailInput(
		attrs = {
			'class':'form-control'
		}
	))

	def clean(self):
		cleaned_data = super().clean()
		aadhar = self.cleaned_data.get('Aadhaar_Number')
		if len(str(aadhar)) != 12:
		    # Only do something if both fields are valid so far.
		    raise forms.ValidationError('invalid aadhar')


	field_order = ['name', 'Aadhaar_Number', 'Email']


	