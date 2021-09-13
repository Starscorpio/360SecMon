from apscheduler.schedulers.background import BackgroundScheduler
from .tasks import mail_send, new_mail_send
from apscheduler.triggers.combining import OrTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta
# from apscheduler.schedulers import Sch
# from apscheduler.schedulers import Scheduler

# Interval of 24 hrs
# trigger = OrTrigger(
#    [CronTrigger(day_of_week='mon-fri', hour='0')])
now = datetime.now()
current_date = now.strftime("%Y-%m-%d")
conv_date = now.strptime(current_date, "%Y-%m-%d")
next_date = conv_date - timedelta(days=1)
str_next_date = str(next_date)
str_split = str_next_date.split(" ")
str_split_one = str_split[0]
conc = current_date + ' 18:30:00'


# Starting the scheduler
def start():
    scheduler = BackgroundScheduler()
    #trigger = CronTrigger(day_of_week='mon-fri', hour='0')
    scheduler.add_job(mail_send, 'interval', seconds=24,
                      start_date=conc)
    scheduler.add_job(new_mail_send, 'interval', seconds=24,
                      start_date=conc)
    scheduler.start()


# Cron job for scheduling email
# def new_start():
##    scheduler = BackgroundScheduler()
    #trigger = CronTrigger(day_of_week='mon-fri', hour='0')
#    scheduler.add_job(new_mail_send, 'interval', seconds=5,
#                      start_date=conc)
#    scheduler.start()
