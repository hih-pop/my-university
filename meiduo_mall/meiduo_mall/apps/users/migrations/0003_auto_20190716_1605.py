# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2019-07-16 16:05
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_user_emall_active'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='emall_active',
            new_name='email_active',
        ),
    ]
