# Generated by Django 3.1.6 on 2021-07-01 20:17

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('securecheck', '0022_auto_20210701_2016'),
    ]

    operations = [
        migrations.RenameField(
            model_name='thekeys',
            old_name='new_ID',
            new_name='ID',
        ),
    ]
