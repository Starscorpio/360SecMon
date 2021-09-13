# Create your views here.
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


# homepage/landingpage after logging in
@login_required(login_url='login')
def home(request):
    context = {}
    current_user = request.user
    # current_username = request.user.username
    # email = current_user.email
    user_id = current_user.id
    now = datetime.now()
    currentmonth = now.strftime('%b')
    db1 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                  database="secmon", auth_plugin="mysql_native_password")
    db2 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                  database="secmon", auth_plugin="mysql_native_password")
    # db3 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    # db4 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    # db5 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    # db6 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    # db7 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    # db8 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    # db9 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                             database="secmon", auth_plugin="mysql_native_password")
    # db10 = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                              database="secmon", auth_plugin="mysql_native_password")
    mycursor = db1.cursor()
    yourcursor = db2.cursor()
    # jancursor = db3.cursor()
    # feb.cursor = db4.cursor()
    # mar.cursor = db5.cursor()
    # apr.cursor = db6.cursor()
    # may.cursor = db7.cursor()
    # jun.cursor = db8.cursor()
    # jul.cursor = db9.cursor()
    # aug.cursor = db10.cursor()
    # janquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Jan' and Status='Expired'"
    # febquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Feb' and Status='Expired'"
    # marquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Mar' and Status='Expired'"
    # aprquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Apr' and Status='Expired'"
    # mayquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='May' and Status='Expired'"
    # junquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Jun' and Status='Expired'"
    # julquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Jul' and Status='Expired'"
    # augquery = "select distinct * from mynewdata where id=" + \
    #    str(user_id) + " and month='Aug' and Status='Expired'"
    dataquery = "select distinct Not_Valid_Before, Not_Valid_After, Subject, Encryption, Status from mynewestdata where id=" + \
        str(user_id)
    trendquery = "select distinct * from mynewestdata where id=" + \
        str(user_id) + " and Status='Expired'"
    mycursor.execute(dataquery)
    yourcursor.execute(trendquery)
    # jancursor.execute(janquery)
    # febcursor.execute(febquery)
    # marcursor.execute(marquery)
    # aprcursor.execute(aprquery)
    # maycursor.execute(mayquery)
    # juncursor.execute(junquery)
    # julcursor.execute(julquery)
    # augcursor.execute(augquery)
    # janresult = jancursor.fetchall()
    # febresult = febcursor.fetchall()
    # marresult = marcursor.fetchall()
    # aprresult = aprcursor.fetchall()
    # mayresult = maycursor.fetchall()
    # junresult = juncursor.fetchall()
    # julresult = julcursor.fetchall()
    # augresult = augcursor.fetchall()
    # len_janresult = len(janresult)
    # len_febresult = len(febresult)
    # len_marresult = len(marresult)
    # len_aprresult = len(aprresult)
    # len_mayresult = len(mayresult)
    # len_junresult = len(junresult)
    # len_julresult = len(julresult)
    # len_augresult = len(augresult)
    myresult = mycursor.fetchall()
    yourresult = yourcursor.fetchall()
    len_yourresult = len(yourresult)
    len_myresult = len(myresult)
    my_result_json = json.dumps(len_myresult)
    your_result_json = json.dumps(len_yourresult)
    list_myresult = list(myresult)
    convertedlist = list(map(list, zip(*list_myresult)))
    if len(convertedlist) > 0:
        start = []
        end = []
        subject = []
        encryption = []
        status = []
        start += convertedlist[0]
        end += convertedlist[1]
        subject += convertedlist[2]
        encryption += convertedlist[3]
        status += convertedlist[4]
        encryption_num = encryption.count("sha256WithRSAEncryption")
        len_encryption_num = len(encryption) - encryption_num
        len_enc_json = json.dumps(len_encryption_num)
        status_num = status.count("Expired")
        len_status_json = json.dumps(status_num)
        context['date_before'] = start
        context['date_after'] = end
        context['sub'] = subject
        context['enc'] = encryption
        context['stat'] = status
        context['id'] = user_id
        context['encjson'] = len_enc_json
        context['statjson'] = len_status_json
        context['resultjson'] = your_result_json
        context['myyresultjson'] = my_result_json
        # context['jan'] = len_janresult
        # context['feb'] = len_febresult
        # context['mar'] = len_marresult
        # context['apr'] = len_aprresult
        # context['may'] = len_mayresult
        # context['jun'] = len_junresult
        # context['jul'] = len_julresult
        # context['aug'] = len_augresult
    return render(request, 'securecheck/home.html', context)


# about/info page
def about(request):
    return render(request, 'securecheck/about.html')


def formsubmission(request):
    form = upload()
    if request.method == "POST":
        form = upload(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_file(request.FILES['file'])
            return HttpResponse("File uploaddedd successfully")

    return render(request, 'securecheck/home.html', {'form': form})


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


def givepass(request):
    context = {}
    return render(request, 'securecheck/pass.html')

# Uploading a PKCS key which also requires a password


def passdata(request):
    context = {}
    current_user = request.user
    current_username = request.user.username
    user_id = current_user.id
    email = current_user.email
    now = datetime.now()
    #user_pass = request.POST.get('file_pass')
    #user_pass = "hello"
    #str_user_pass = str(user_pass)
    str_user_pass = request.POST.get('file_pass')
    currentmonth = now.strftime('%b')
    pass_file_data = request.FILES.getlist('pkcs')
    #another_split_file = pass_file_data.split(" ")
    #another_split_file_final = another_split_file[1::3]
    read_file = open('/Users/starscorp1o/certs/identity.p12', 'rb')
    read_that_file = str(read_file.read())
    read_that_file_bytes = bytes(read_that_file, 'utf-8')
    str_files = str(pass_file_data)
    split = str_files.split(" ")
    split_files = split[1::3]
    for x in split_files:
        p12 = crypto.load_pkcs12(open(
            '/Users/starscorp1o/certs/' + x, 'rb').read(), str_user_pass.encode('utf-8'))
        cert = p12.get_certificate()
        pkey = p12.get_privatekey()
        pkey_bits = pkey.bits()
        pkey_algo = "sha256withRSAalgorithm"
        cert_subject = cert.get_subject()
        cert_subject_CN = cert_subject.CN
        cert_Not_Valid_Before = cert.get_notBefore().decode('utf-8')
        cert_Not_Valid_After = cert.get_notAfter().decode('utf-8')
        cert_enc = cert.get_signature_algorithm().decode('utf-8')
        #x_read = x.read()
        #x_bytes = bytes(x_read, 'utf-8')
        #cert_finger = cert.get_fingerprint('sha-1').decode('utf-8')
        #cert_issuerhash = cert.getIssuerHash().decode('utf-8')
        #cert_modulus = cert.getModulus().decode('utf-8')
        #cert_ocspid = cert.getOcspId()
        #cert_subjecthash = cert.getSubjectHash()
        exp = "Expired"
        #our = x
        fileInfo = form(name='imppp', file=x, cont=read_that_file_bytes, userid=user_id, username=current_username, email=email, month=currentmonth, Not_Valid_Before=cert_Not_Valid_Before,
                        Not_Valid_After=cert_Not_Valid_After, Subject=cert_subject_CN, Encryption=cert_enc, Status=exp, Revocation_status="last_ocsp_result_one", fingerprint="cert_finger", issuer_hash="cert_issuerhash", modulus="cert_modulus", ocspid="cert_ocspid", sub_hash="subjecthash", alias_name="cert_alias", serial_no="serial_number", sub_hash_old="subjecthashold", issuer_hash_old="issuerhashold", cert_email="email_on_cert", cert_purpose="purpose_of_cert", ocspuri="ocspuri_cert", location="", location_status="")
        fileInfo.save()
        keyInfo = thekeys(username=current_username, email=email, month=currentmonth,
                          Encryption=pkey_algo, Number_of_bits=pkey_bits)
        keyInfo.save()
    context['filedata'] = pass_file_data
    return redirect('newanalytics')


# Analytics page after uploading file/s
def newanalytics(request):
    context = {}
    current_user = request.user
    current_username = request.user.username
    user_id = current_user.id
    email = current_user.email
    now = datetime.now()
    currentmonth = now.strftime('%b')

# If a GET request is made to the page
    if request.method == "GET":
        information = form.objects.values(
            'Subject', 'Encryption', 'Status', 'Not_Valid_After', 'id', 'location_status').distinct()

# If a POST request is made to the page
    elif request.method == "POST":
        files = request.FILES.getlist('filess')
        str_files = str(files)
        split = str_files.split(" ")
        split_files = split[1::3]
        len_split_files = len(split_files)

        for h in split_files:
            file_uploaded = open(
                '/Users/starscorp1o/security_project/security_monitoring_project/media/securecheck/uploaded_files/djangoserver.txt', 'rb')
            data_data = str(file_uploaded.read())
            data_data_conv = bytes(data_data, 'utf-8')

# Iterating over user file/s input
        for y in files:
            # Certificates with .txt extension
            if y.name.endswith('.txt'):
                file_read = y.read().strip().decode('utf-8')
                newcert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, file_read)
                newcert_subject = newcert.get_subject().CN
                newcert_exp = str(newcert.has_expired())
                if str(newcert_exp) == 'True':
                    exp = "Expired"
                else:
                    exp = "Not Expired"
                newcert_notafter = datetime.strptime(
                    str(newcert.get_notAfter().strip().decode('utf-8')), "%Y%m%d%H%M%SZ")
                newcert_notafter_conv = datetime.strftime(
                    newcert_notafter, '%b %d %H:%M:%S %Y %Z GMT')
                newcert_notbefore = datetime.strptime(
                    str(newcert.get_notBefore().strip().decode('utf-8')), "%Y%m%d%H%M%SZ")
                newcert_notbefore_conv = datetime.strftime(
                    newcert_notbefore, '%b %d %H:%M:%S %Y %Z GMT')
                newcert_issuer = newcert.get_issuer()
                newcert_ser_number = str(newcert.get_serial_number())
                newcert_version = newcert.get_version()
                newcert_sig_algo = newcert.get_signature_algorithm().decode('utf-8')
                newcert_sub_hash = str(newcert.subject_name_hash())
                extensions = (newcert.get_extension(i)
                              for i in range(newcert.get_extension_count()))
                extension_data = {e.get_short_name(): str(e).strip()
                                  for e in extensions}
                str_extension_data = str(extension_data)
                ext_result = re.search(
                    "CA Issuers - URI:(.*)basic", str_extension_data)
                ext_result_one = ext_result.group(1)
                new_ext = newcert.get_extension(1)
                newcert_name = y.name
                #newcert_enc = newcert_name.encode('utf-8')
                diff_format_cert = x509.load_pem_x509_certificate(
                    file_read.encode('ascii'), default_backend())
                aia = diff_format_cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
                issuers = [ia for ia in aia if ia.access_method ==
                           AuthorityInformationAccessOID.CA_ISSUERS]
                if not issuers:
                    raise Exception(f'no issuers entry in AIA')
                issuer_res = issuers[0].access_location.value
                cert_fingerprint = diff_format_cert.fingerprint()
                fileInfo = form(name='imppp', file=newcert_name, cont=file_read.encode('utf-8'), userid=user_id, username=current_username, email=email, month=currentmonth, Not_Valid_Before=newcert_notbefore_conv,
                                Not_Valid_After=newcert_notafter_conv, Subject=newcert_subject, Encryption=newcert_sig_algo, Status=exp, Revocation_status="Not revoked", fingerprint="soemthing", issuer_hash="issuerhash", modulus="certmodulus", ocspid="cert_ocspid", sub_hash=newcert_sub_hash, alias_name="cert_alias", serial_no=newcert_ser_number, sub_hash_old="subjecthashold", issuer_hash_old="issuerhashold", cert_email="email_on_cert", cert_purpose="purpose_of_cert", ocspuri="ocspuri_cert", location="", location_status="")
                fileInfo.save()
                context['readfile'] = file_read
                context['xsub'] = newcert_subject
                context['newcertexp'] = newcert_exp
                context['newcertnotafter'] = newcert_notafter
                context['newcertnotbefore'] = newcert_notbefore
                context['newcertnotafterconv'] = newcert_notafter_conv
                context['newcertissuer'] = newcert_issuer
                context['newcertsernumber'] = newcert_ser_number
                context['newcertversion'] = newcert_version
                context['newcertsigalgo'] = newcert_sig_algo
                context['newcertsubhash'] = newcert_sub_hash
                context['newcertextensions'] = extensions
                context['newcertextdata'] = extension_data
                context['extresultone'] = ext_result_one
                context['newextt'] = new_ext
                context['newcertname'] = newcert_name
                context['issuerres'] = issuer_res
# Keys with .pem extension
            elif y.name.endswith('.pem'):
                key_file_read = y.read().strip().decode('utf-8')
                key_file_load = OpenSSL.crypto.load_publickey(
                    OpenSSL.crypto.FILETYPE_PEM, key_file_read)
                key_file_bits = key_file_load.bits()
                key_file_type = key_file_load.type()
                keyInfo = thekeys(username=current_username, email=email, month=currentmonth,
                                  Encryption=key_file_type, Number_of_bits=key_file_bits)
                keyInfo.save()
                #key_algo = key.get_signature_algorithm()
# Keystore with .pkcs12 extension
            elif y.name.endswith('.p12'):
                return redirect('pass')
# Keys with .pub extension
            elif y.name.endswith('.pub'):
                some = "kjslkj"
                keyInfo = thekeys(username=current_username, email=email, month=currentmonth,
                                  Encryption="sdfsdf", Number_of_bits="pkey_bits")
                keyInfo.save()
            information_count = form.objects.all().distinct().count()
            all_certs = secfile.objects.filter(
                Status__exact="Expired").distinct().count()
            all_certs_json = json.dumps(all_certs)
            all_certs_rev = secfile.objects.filter(
                Revocation_status__exact="OCSPCertStatus.REVOKED").distinct().count()
            all_certs_rev_json = json.dumps(all_certs_rev)
            all_certs_enc = secfile.objects.filter(
                Encryption__exact="sha256WithRSAEncryption").distinct().count()
            all_certs_enc_json = json.dumps(all_certs_enc)
            minus = information_count - all_certs_enc
            minus_json = json.dumps(minus)
            add_all_certs = all_certs + all_certs_rev + minus
            information = form.objects.values(
                'Subject', 'Encryption', 'Status', 'Not_Valid_After', 'id', 'location').distinct()
            information_count_new = form.objects.values(
                'Subject', 'Encryption', 'Status', 'Not_Valid_After').distinct().count()
            information_count_new_json = json.dumps(information_count_new)
            security_keys = thekeys.objects.all()

# Declaring all variables which then can be used in the html template
        #context['hii'] = startdate_decoded_new
        #context['lenthy'] = len_split_files
        # context['hiii'] = allsplit
        #context['hiiii'] = subject_decoded_new
        # context['hiiiii'] = enc_decoded
        #context['yono'] = enddate_decoded_new
        #context['yelling'] = enc_decoded_new
        # context['crt'] = enc_up_json
        #context['football'] = exp_up_json
        # context['gasping'] = enddate_2_decoded
        # context['go'] = subject_2_decoded
        # context['goal'] = countjson
        # context['countstring'] = totaljson
        # keys
        #context['tea'] = ssh_decoded_new
        #context['algo'] = algo_decoded_new
        #context['dom'] = algo_decoded_new_count
        # context['cuser'] = current_user
        # context['id'] = user_id
        # context['mail'] = email
        # context['neweste'] = newe
        # database
        #context['theresult'] = start
        #context['theresulting'] = end
        #context['theresulted'] = subject
        #context['thereale'] = enc
        # context['therealeste'] = eeeeeee
        #context['finalresult'] = status
        context['id'] = user_id
        #context['county'] = len_enc_count_json
        #context['newlen'] = status_count_json
        #context['plz_keys'] = keys
        # context['generation'] = newgen
        # context['generation1'] = newgen1
        # context['generation2'] = newgen2
        # context['gensec'] = gen
        # context['gensec1'] = gen1
        # context['gensec2'] = gen2
        # context['gensec3'] = gen3
        # context['gensec4'] = gen4
        # context['curmonth'] = currentmonth
        # context['execute'] = exec
        #context['expi'] = new_exp
        #context['wording'] = word
        #context['wording1'] = word1
        #context['wording2'] = word2
        #context['wording3'] = word3
        #context['wording4'] = word4
        #context['wording5'] = word5
        #context['ssl_pem_bits'] = pem_bits_decoded_new
        #context['ssl_algo'] = algo_pem_actual
        #context['got_that_ocsp'] = count_ocsp_json
        #context['keysbits'] = keys_bits
        #context['keysenc'] = keys_enc
        #context['win'] = gotresult
        context['allcerts'] = all_certs_json
        #context['infojson'] = information_count_new_json
        #context['keyssha'] = keys_sha
        #context['filedata'] = file_data
        #context['keysjson'] = keys_count_json
        context['allbadcerts'] = add_all_certs
        context['revjson'] = all_certs_rev_json
        context['badencjson'] = all_certs_enc_json
        context['minusjson'] = minus_json
        #context['subhash'] = subjecthash
        #context['issuerhash'] = issuerhash
        #context['certfing'] = certfingerprint
        #context['certmod'] = certmodulus
        #context['certocspid'] = cert_ocspid
        #context['certalias'] = cert_alias
        #context['sernum'] = serial_number
        #context['oldhashsub'] = subjecthashold
        #context['oldhashissuer'] = issuerhashold
        #context['certemail'] = email_on_cert
        #context['certpurpose'] = purpose_of_cert
        #context['certocspuri'] = ocspuri_cert
        #context['keyalgo'] = key_algo
        #context['newcertdigest'] = newcert_digest
        #context['newcerthash'] = newcert_hash
        # context['text'] = text_format
        # context['exprev'] = all_certs_exp_rev
        # context['expcerts'] = newexpiry
        # context['hiiiii'] = ocsp_uri_decoded
        # context['yoyo'] = ocsp_uri_decoded
        #context['yessskeys'] = yoookeys
        #context['security_all_keys'] = security_keys
    context['info'] = information

    return render(request, 'securecheck/analytics.html', context)


def newinfo(request, id):
    context = {}
    info_all = form.objects.get(id=id)
    context['allinfo'] = info_all
    return render(request, 'securecheck/info.html', context)
# Html to pdf


def render_to_pdf(template_src, context_dict):
    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type='application/pdf')
    return None

    class GeneratePDF(View):
        def get(self, request, *args, **kwargs):
            template = get_template('email.html')
            context = {
                "invoice_id": 123,
                "customer_name": "John Cooper",
                "amount": 1399.99,
                "today": "Today",
            }
            html = template.render(context)
            pdf = render_to_pdf('email.html', context)
            if pdf:
                response = HttpResponse(pdf, content_type='application/pdf')
                filename = "Invoice_%s.pdf" % ("12341231")
                content = "inline; filename='%s'" % (filename)
                download = request.GET.get("download")
                if download:
                    content = "attachment; filename='%s'" % (filename)
                response['Content-Disposition'] = content
                return response
            return HttpResponse("Not found")


# Another Html to pdf
class Pdf(View):

    def get(self, request):
        sales = ""
        today = "yo"
        params = {
            'today': today,
            'sales': sales,
            'request': request
        }
        context = {}
        current_user = request.user
        current_username = request.user.username
        user_id = current_user.id
        email = current_user.email
        pdfdb = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                        database="secmon", auth_plugin="mysql_native_password")
        pdfcursor = pdfdb.cursor()
        x = "select distinct Not_Valid_Before, Not_Valid_After, Subject, Encryption, Status from mynewestdata where id=" + \
            str(user_id)
        pdfcursor.execute(x)
        pdfresult = pdfcursor.fetchall()
        list_result = list(pdfresult)
        count_list_result = list_result[0]
        count_list_result_2 = list_result[1]
        convlist = list(map(list, zip(*list_result)))
        start = []
        end = []
        subject = []
        enc = []
        status = []
        if len(convlist) > 0:
            start += convlist[0]
            end += convlist[1]
            subject += convlist[2]
            enc += convlist[3]
            status += convlist[4]
        context['theresult'] = count_list_result
        context['theresulting'] = count_list_result_2
        context['theresulted'] = subject
        context['thereale'] = enc
        # context['therealeste'] = eeeeeee
        context['finalresult'] = status
        pdf = render_to_pdf('securecheck/email.html', context)
        return HttpResponse(pdf, content_type='application/pdf')


def new(request):
    context = {}
    current_user = request.user
    current_username = request.user.username
    user_id = current_user.id
    email = current_user.email
    pdfdb = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                    database="secmon", auth_plugin="mysql_native_password")
    pdfcursor = pdfdb.cursor()
    x = "select distinct Not_Valid_Before, Not_Valid_After, Subject, Encryption, Status from mynewestdata where id=" + \
        str(user_id)
    pdfcursor.execute(x)
    pdfresult = pdfcursor.fetchall()
    list_result = list(pdfresult)
    count_list_result = list_result[0]
    count_list_result_2 = list_result[1]
    # newlist = list(zip(*list_result))
    convlist = list(map(list, zip(*list_result)))
    start = []
    end = []
    subject = []
    enc = []
    status = []
    if len(convlist) > 0:
        start += convlist[0]
        end += convlist[1]
        subject += convlist[2]
        enc += convlist[3]
        status += convlist[4]
    context['theresult'] = count_list_result
    context['theresulting'] = end
    context['theresulted'] = subject
    context['thereale'] = enc
    context['name'] = current_username
    context['therealeste'] = convlist
    context['finalresult'] = status
    pdf = render_to_pdf('securecheck/email.html', context)
    return HttpResponse(pdf, content_type='application/pdf')


# Html to Pdf - Keys
def keys(request):
    context = {}
    current_user = request.user
    # current_username = request.user.username
    # user_id = current_user.id
    # email = current_user.email
    # pdfdb = mysql.connector.connect(host="localhost", user="root", password="toor1234",
    #                               database="secmon", auth_plugin="mysql_native_password")
    # pdfcursor = pdfdb.cursor()
    # x = "select distinct Not_Valid_Before, Not_Valid_After, Subject, Encryption, Status from mynewestdata where id=" + \
    #    str(user_id)
    # pdfcursor.execute(x)
    # pdfresult = pdfcursor.fetchall()
    newexpiry = secfile.objects.filter(Status__exact="Expired")[:8]
    information = secfile.objects.all().distinct()
    revd = secfile.objects.filter(
        Revocation_status__exact="OCSPCertStatus.REVOKED")[:10]
    get_keys = thekeys.objects.all()
    context['revdd'] = revd
    context['info'] = information
    context['expcerts'] = newexpiry
    context['name'] = current_user
    context['get_the_keys'] = get_keys
    # context['therealeste'] = eeeeeee
    # context['finalresult'] = status
    pdf = render_to_pdf('securecheck/keys_pdf.html', context)
    return HttpResponse(pdf, content_type='application/pdf')


def revoked(request):
    context = {}
    current_user = request.user
    current_username = request.user.username
    user_id = current_user.id
    email = current_user.email
    pdfdb = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                    database="secmon", auth_plugin="mysql_native_password")
    pdfcursor = pdfdb.cursor()
    x = "select distinct Not_Valid_Before, Not_Valid_After, Subject, Encryption, Status from mynewestdata where id=" + \
        str(user_id)
    pdfcursor.execute(x)
    pdfresult = pdfcursor.fetchall()
    list_result = list(pdfresult)
    count_list_result = list_result[0]
    count_list_result_2 = list_result[1]
    convlist = list(map(list, zip(*list_result)))
    start = []
    end = []
    subject = []
    enc = []
    status = []
    if len(convlist) > 0:
        start += convlist[0]
        end += convlist[1]
        subject += convlist[2]
        enc += convlist[3]
        status += convlist[4]
    context['theresult'] = count_list_result
    context['theresulting'] = count_list_result_2
    context['theresulted'] = subject
    context['thereale'] = enc
    context['name'] = current_username
    # context['therealeste'] = eeeeeee
    context['finalresult'] = status
    pdf = render_to_pdf('securecheck/keys_pdf.html', context)
    return HttpResponse(pdf, content_type='application/pdf')


# Total certs - seperate page with table when clicked on total certs card
def tcerts(request):
    context = {}
    information = secfile.objects.all().distinct()
    context['info'] = information
    return render(request, 'securecheck/total_certs.html', context)


# Total Keys - seperate page with table when clicked on total keys card
def tkeys(request):
    context = {}
    keys = thekeys.objects.all().distinct()
    context['ourkeys'] = keys
    return render(request, 'securecheck/total_keys.html', context)


# Expired certs - seperate page with table when clicked on piechart(expired section)
def ecerts(request):
    context = {}
    newexpiry = secfile.objects.filter(Status__exact="Expired")
    context['expcerts'] = newexpiry
    return render(request, 'securecheck/exp_certs.html', context)


def rcerts(request):
    context = {}
    newexpiry = secfile.objects.filter(
        Revocation_status__exact="OCSPCertStatus.REVOKED")
    context['revcerts'] = newexpiry
    return render(request, 'securecheck/revoked_certs.html', context)


# Revoked certs - seperate page with table when clicked on piechart(revoked section)
def expcertss(request):
    context = {}
    all_certs_rev = secfile.objects.filter(
        Revocation_status__exact="OCSPCertStatus.REVOKED")
    all_certs_exp = secfile.objects.filter(
        Status__exact="Expired")
    some_func = something()
    notsha = secfile.objects.filter(
        Encryption__exact="ecdsa-with-SHA384")
    notsha1 = secfile.objects.filter(
        Encryption__exact="ecdsa-with-SHA256")
    all_exp_certs = form.objects.filter(Status__exact="Expired")
    all_rev_certs = form.objects.filter(
        Revocation_status__exact="OCSPCertStatus.REVOKED")
    all_three = form.objects.filter(
        Encryption__exact="ecdsa-with-SHA384")
    all_two = form.objects.filter(
        Encryption__exact="ecdsa-with-SHA256")
    context['exprev'] = all_rev_certs
    context['exp'] = all_three
    context['somefunc'] = all_two
    context['not_sha'] = notsha
    context['not_sha1'] = notsha1
    context['more_exp_certs'] = all_exp_certs
    return render(request, 'securecheck/expcerts.html', context)


# Just testing
def testing(request):
    context = {}
    all_certs_exp = secfile.objects.filter(
        Status__exact="Expired")
    form_data = form.objects.all()
    context['exp'] = all_certs_exp
    context['formdata'] = form_data
    return render(request, 'securecheck/testing.html', context)


def anothertest(request, id):
    context = {}
    delreq = form.objects.get(id=id)
    delreq.delete()
    form_data = form.objects.all()
    context['formdata'] = form_data
    return redirect('newanalytics')


def total_certs_page(request, id):
    context = {}
    delreq = form.objects.get(id=id)
    delreq.delete()
    form_data = form.objects.all()
    context['formdata'] = form_data
    return redirect('expcerts')


def onemoretest(request, id):
    context = {}
    delreq = form.objects.get(id=id)
    delreq.delete()
    return render(request, 'securecheck/update.html', context)


def keystest(request, key_id):
    context = {}
    delreq = thekeys.objects.get(key_id=key_id)
    delreq.delete()
    context['del'] = delreq
    return redirect('bkeys')


def not_enc(request):
    context = {}
    notenc = thekeys.objects.filter(Encryption__exact='SHA1')
    context['nottheenc'] = notenc
    return render(request, 'securecheck/onlyenc.html', context)


def not_len(request):
    context = {}
    notlen = thekeys.objects.filter(Number_of_bits__exact='2048')
    context['notthelen'] = notlen
    return render(request, 'securecheck/onlylen.html', context)


def keys_update(request, key_id):
    context = {}
    delreq = thekeys.objects.get(key_id=key_id)
    delreq.delete()
    return render(request, 'securecheck/update.html', context)


# Bad keys - Revoked or Length too small - seperate page with table when clicked on bad keys card
def bkeys(request):
    context = {}
    keys = thekeys.objects.values(
        'key_id', 'Number_of_bits', 'Encryption', 'email', 'month', 'username')
    context['ourkeys'] = keys
    return render(request, 'securecheck/badkeys.html', context)


def notify(request):
    context = {}
    data = ""
    msg = ""
    new_freq_data = ""
    new_freq_msg = ""
    new_f_data = ""
    '''if request.POST.get('vehicle1') == "15":
        data = request.POST.get("vehicle1")
        msg = "Updated to 15 days successfully"
        noted = notifi(actual_data=data, message_display=msg)
        noted.save()
    elif request.POST.get('vehicle2') == "30":
        data = request.POST.get("vehicle2")
        msg = "Updated to 30 days successfully"
        noted = notifi(actual_data=data, message_display=msg)
        noted.save()
    elif request.POST.get('vehicle3') == "45":
        data = request.POST.get("vehicle3")
        msg = "Updated to 45 days successfully"
        noted = notifi(actual_data=data, message_display=msg)
        noted.save()
    elif request.POST.get('vehicle4') == "60":
        data = request.POST.get("vehicle4")
        msg = "Updated to 60 days successfully"
        noted = notifi(actual_data=data, message_display=msg)
        noted.save()'''
    data = request.POST.get("vehicle5")
    str_data = str(data)
    if len(str_data) > 0:
        msg = "Updated to " + str_data + " days successfully"
        noted = notifi(actual_data=data, message_display=msg)
        noted.save()
    else:
        msg = ""
        pass
    '''elif request.POST.get('7days') == "7":
        new_freq_data = request.POST.get("7days")
        new_freq_msg = "Updated to repeat after 7 days"
        notery = freq(freq_data=new_freq_data, freq_msg=new_freq_msg)
        notery.save()
    elif request.POST.get('10days') == "10":
        new_freq_data = request.POST.get("10days")
        new_freq_msg = "Updated to repeat after 10 days"
        notery = freq(freq_data=new_freq_data, freq_msg=new_freq_msg)
        notery.save()
    elif request.POST.get('15days') == "15":
        new_freq_data = request.POST.get("15days")
        new_freq_msg = "Updated to repeat after 15 days"
        notery = freq(freq_data=new_freq_data, freq_msg=new_freq_msg)
        notery.save()
    elif request.POST.get('20days') == "20":
        new_freq_data = request.POST.get("20days")
        new_freq_msg = "Updated to repeat after 20 days"
        notery = freq(freq_data=new_freq_data, freq_msg=new_freq_msg)
        notery.save()'''
    # elif request.POST.get('vehicle6') != '7' or '10' or '15' or '20':
    #    new_freq_data = request.POST.get("vehicle6")
    #    new_freq_msg = "Updated to " + \
    #        str(new_freq_data) + " days successfully"
    #    notery = freq(freq_data=new_freq_data, freq_msg=new_freq_msg)
    #    notery.save()
    gett = notifi.objects.latest('data_id')
    freqq = freq.objects.latest('new_id')
    heii = gett.data_id
    #new_f_data = freq.objects.latest('new_id')
    context['ff_data'] = new_freq_data
    context['ff_msg'] = new_freq_msg
    context['new_ff_data'] = new_f_data
    context['info'] = data
    context['message'] = msg
    context['gott'] = gett
    context['hi'] = heii
    context['frequency'] = freqq
    return render(request, 'securecheck/notification.html', context)


def location(request, id):
    context = {}
    loc = request.POST.get("location")
    req = form.objects.get(id=id)
    req.location = loc
    req.save()
    if req.location == loc:
        req.location_status = "location added"
        req.save()
    return redirect('newanalytics')


# def newloc(request, id):
#    context = {}
#    loc = request.POST.get("location")
#    req = form.objects.get(id=id)
#    req.location = loc
#    req.save()
#    return redirect('newanalytics')


def note(request):
    context = {}
    if request.method == "POST":
        data = ""
        msg = ""
        if request.POST.get('vehicle1') == "15":
            data = request.POST.get("vehicle1")
        elif request.POST.get('vehicle2') == "30":
            data = request.POST.get("vehicle2")
        elif request.POST.get('vehicle3') == "45":
            data = request.POST.get("vehicle3")
        elif request.POST.get('vehicle4') == "60":
            data = request.POST.get("vehicle4")
        int_data = int(data)
    return int_data


# Deleting records from table
# def deleterec(request, pk):
    # some = get_object_or_404(secfile, pk=pk)
    # some.delete()
    # return redirect('/')
