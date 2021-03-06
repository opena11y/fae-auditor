# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2018-10-25 20:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('websiteResults', '0003_auto_20181024_1326'),
    ]

    operations = [
        migrations.AlterField(
            model_name='websiteguidelineresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiteguidelineresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiteresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiteresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiteruleresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiteruleresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, max_digits=4),
        ),
    ]
