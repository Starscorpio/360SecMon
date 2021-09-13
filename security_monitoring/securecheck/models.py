from django.db import models
from django.db import connections

# Create your models here.


# Collecting the uploaded files and storing its local path in the database
class form(models.Model):
    name = models.CharField(max_length=64)
    file = models.FileField(
        upload_to='securecheck/uploaded_files', blank=True)
    cont = models.BinaryField(blank=True, editable=False)
    userid = models.IntegerField(blank=True, null=True)
    username = models.CharField(max_length=100, default=None)
    email = models.CharField(max_length=100, default=None)
    month = models.CharField(max_length=100, default=None)
    Not_Valid_Before = models.CharField(max_length=100, default=None)
    Not_Valid_After = models.CharField(max_length=100, default=None)
    Subject = models.CharField(max_length=100, default=None)
    Encryption = models.CharField(max_length=100, default=None)
    Status = models.CharField(max_length=100, default=None)
    Revocation_status = models.CharField(max_length=100, default=None)
    modulus = models.CharField(max_length=1000, default=None)
    issuer_hash = models.CharField(max_length=1000, default=None)
    fingerprint = models.CharField(max_length=1000, default=None)
    alias_name = models.CharField(max_length=1000, default=None)
    ocspid = models.CharField(max_length=1000, default=None)
    sub_hash = models.CharField(max_length=1000, default=None)
    serial_no = models.CharField(max_length=1000, default=None)
    sub_hash_old = models.CharField(max_length=1000, default=None)
    issuer_hash_old = models.CharField(max_length=1000, default=None)
    cert_email = models.CharField(max_length=1000, default=None)
    cert_purpose = models.CharField(max_length=1000, default=None)
    ocspuri = models.CharField(max_length=1000, default=None)
    location = models.CharField(max_length=100, default=None)
    location_status = models.CharField(max_length=100, default=None)


# Saving the parameters of certificates in the database so that we can extract and display them later
class secfile(models.Model):
    Id = models.IntegerField(max_length=100)
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    month = models.CharField(max_length=100)
    Not_Valid_Before = models.CharField(max_length=100)
    Not_Valid_After = models.CharField(max_length=100)
    Subject = models.CharField(max_length=100)
    Encryption = models.CharField(max_length=100)
    Status = models.CharField(max_length=100)
    Revocation_status = models.CharField(max_length=100, default=None)
# Table where certificate parameters have been saved

    class Meta:
        db_table = "finaldata"


# Saving the parameters of keys in the database so that we can extract and display them later
class thekeys(models.Model):
    month = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    Number_of_bits = models.CharField(max_length=100)
    Encryption = models.CharField(max_length=100)
    key_id = models.AutoField(primary_key=True, default=None)
# Table where key parameters have been saved


class notifi(models.Model):
    data_id = models.AutoField(primary_key=True)
    actual_data = models.CharField(max_length=100, null=True)
    message_display = models.CharField(max_length=1000, null=True)


class freq(models.Model):
    new_id = models.AutoField(primary_key=True)
    freq_data = models.CharField(max_length=100, null=True)
    freq_msg = models.CharField(max_length=100, null=True)
