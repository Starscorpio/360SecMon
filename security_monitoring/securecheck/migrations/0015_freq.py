# Generated by Django 3.1.6 on 2021-06-02 16:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('securecheck', '0014_auto_20210601_1159'),
    ]

    operations = [
        migrations.CreateModel(
            name='freq',
            fields=[
                ('new_id', models.AutoField(primary_key=True, serialize=False)),
                ('freq_data', models.CharField(max_length=100)),
                ('freq_msg', models.CharField(max_length=100)),
            ],
        ),
    ]