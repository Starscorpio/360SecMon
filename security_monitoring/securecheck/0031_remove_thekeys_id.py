# Generated by Django 3.1.6 on 2021-07-02 10:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('securecheck', '0030_thekeys_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='thekeys',
            name='ID',
        ),
    ]
