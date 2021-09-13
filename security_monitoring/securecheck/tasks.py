from datetime import datetime, date
import schedule
import time
from django.core.mail import send_mail
from datetime import datetime, timedelta
import mysql.connector


# Connecting to the MySQL database
db = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                  database="secmon", auth_plugin="mysql_native_password")
dbcursor = db.cursor()

newdb = mysql.connector.connect(host="localhost", user="root", password="toor1234",
                                database="secmon", auth_plugin="mysql_native_password")
newcursor = newdb.cursor()

now = datetime.now()


# Send email to user when certificate will expire in 30 days and resend an email when the same certificate has not been updated after a week
def mail_send():
    query = "select distinct Not_Valid_After, email from mynewestdata"
    dbcursor.execute(query)
    newresult = dbcursor.fetchall()
    list_newresult = list(newresult)
    converted_list = list(map(list, zip(*list_newresult)))
    expiry_date = []
    email_addr = []
    expiry_date += converted_list[0]
    email_addr += converted_list[1]
    gett = notifi.objects.latest('data_id')
    freqq = freq.objects.latest('new_id')
    data_freq = freqq.freq_data
    update_no = gett.actual_data
    int_data_freq = int(data_freq)
    int_update_no = int(update_no)
    thirty = timedelta(int_update_no)
    two_three = timedelta(int_update_no - int_data_freq)
    # for b in expiry_date:
    date_then = now + thirty
    date_after_then = now + two_three
    newdates = datetime.strptime(
        'May  8 10:35:50 2021 GMT', "%b %d %H:%M:%S %Y %Z")
    if newdates > date_after_then:
        new_string = "ok, notification already sent"
    elif newdates <= date_after_then:
        send_mail('Test Email', 'Another email has you had forgot to upgrade your cert' + 'nottt' + ' now you get it?',
                  'vedant.tare@gmail.com', ['vedant.tare@gmail.com'])
    if newdates > date_then:
        string = "still ok"
    elif newdates <= date_then:
        send_mail('Test Email', 'These are your certs -> probably not expired Their status is -> ' + 'wohoooitsworking' + ' there you go',
                  'vedant.tare@gmail.com', ['vedant.tare@gmail.com'])


# Another function to test email feature
def new_mail_send():
    newquery = "select distinct Not_Valid_After, email from mynewestdata"
    newcursor.execute(newquery)
    new_result = newcursor.fetchall()
    list_new_result = list(new_result)
    converted_list_new = list(map(list, zip(*list_new_result)))
    expiry_date = []
    email_addr = []
    expiry_date += converted_list_new[0]
    email_addr += converted_list_new[1]
    # for b in expiry_date:
    date_then_also = now + timedelta(30)
    date_after_then_also = now + timedelta(23)
    newdates = datetime.strptime(
        'May  8 10:35:50 2021 GMT', "%b %d %H:%M:%S %Y %Z")
    if newdates > date_after_then_also:
        new_string = "ok, notification already sent"
    elif newdates <= date_after_then_also:
        send_mail('Test Email', 'Another email has you had forgot to upgrade your cert' + 'nottt' + ' now you get it?',
                  'vedant.tare@gmail.com', ['vedant.tare@gmail.com'])


def something():
    context = {}
    hello = "helloooo"
    context['ohello'] = hello
    return hello
