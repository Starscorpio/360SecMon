# Just testing some code
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.http import JsonResponse
import requests
import subprocess
import ssl
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import mysql.connector
import os
from cryptography.x509.ocsp import OCSPResponseStatus
from securecheck.forms import upload
from securecheck.functions.functions import handle_uploaded_file
from cryptography.x509 import load_pem_x509_certificate, ocsp
from securecheck.models import form
from securecheck.models import secfile
from pathlib import Path
from cryptography.x509 import ocsp
from django.conf import settings
import re
from datetime import datetime, timedelta
import datetime
import json
from ocspbuilder import OCSPRequestBuilder
from ocspbuilder import OCSPResponseBuilder
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from .models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMessage
import pdfkit
from io import BytesIO
from xhtml2pdf import pisa
from django.views.generic import View
from django.template.loader import get_template
from django.template import Context
from django.http import HttpResponse
import schedule
from freezegun import freeze_time
from datetime import datetime, date
import schedule
import time
import base64
import ssl
import requests
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from datetime import datetime, date
import datetime
import schedule
import time
from django.core.mail import send_mail
from datetime import datetime
from securecheck.tasks import something
import tkinter as tk
from tkinter import simpledialog
from OpenSSL import crypto


# Register/signup page
def registerPage(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        form = CreateUserForm()
        if request.method == 'POST':
            form = CreateUserForm(request.POST)
            if form.is_valid():
                form.save()
                user = form.cleaned_data.get('username')
                messages.success(request, 'Account was created for ' + user)

                return redirect('login')

        context = {'form': form}
        return render(request, 'securecheck/register.html', context)


# Login page
def loginPage(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                messages.info(request, 'Username or password is incorrect')

        context = {}
        return render(request, 'securecheck/login.html', context)


# Logout
def logoutUser(request):
    logout(request)
    return redirect('login')
