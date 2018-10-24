# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2018-10-17 21:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('websiteResults', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='websiteguidelineresult',
            name='slug',
            field=models.SlugField(blank=True, default='none', editable=False, max_length=64),
        ),
        migrations.AlterField(
            model_name='websiteresult',
            name='data_dir_slug',
            field=models.SlugField(editable=False, max_length=64),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresult',
            name='slug',
            field=models.SlugField(blank=True, default='none', editable=False, max_length=64),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesult',
            name='slug',
            field=models.SlugField(blank=True, default='none', editable=False, max_length=64),
        ),
    ]