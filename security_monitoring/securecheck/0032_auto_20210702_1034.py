# Generated by Django 3.1.6 on 2021-07-02 10:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('securecheck', '0031_remove_thekeys_id'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='thekeys',
            new_name='the_keys',
        ),
    ]