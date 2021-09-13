from django.apps import AppConfig


class SecurecheckConfig(AppConfig):
    name = 'securecheck'
# Calling the send email task/scheduler

#    def ready(self):
#        from .import updater
#        updater.start()
