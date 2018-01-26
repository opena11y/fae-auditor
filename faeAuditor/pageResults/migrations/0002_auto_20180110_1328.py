# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2018-01-10 19:28
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('pageResults', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pageruleresult',
            name='rule',
            field=models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, to='rules.Rule'),
        ),
        migrations.AlterField(
            model_name='pageruleresult',
            name='slug',
            field=models.SlugField(blank=True, default='', editable=False, max_length=32),
        ),
    ]