from django import forms
from django.contrib.auth.forms import AuthenticationForm


class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'name@example.com', 'autofocus': True, 'id': 'floatingInput'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password', 'id': 'floatingPassword'}))
    remember_me = forms.BooleanField(required=False, label='Remember me', widget=forms.CheckboxInput(attrs={'class': 'checkbox mb-3', 'type': 'checkbox', 'value': '', 'id': 'flexCheckDefault'}))