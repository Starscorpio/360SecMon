from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


# Multiple files can be uploaded
class upload(forms.Form):
    file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={'multiple': True}))


# User registration form
class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
