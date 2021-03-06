# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2018-10-31 03:23
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auditGroup2Results', '0007_auto_20181026_1039'),
    ]

    operations = [
        migrations.AddField(
            model_name='auditgroup2guidelineresult',
            name='total_pages_fail',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditgroup2result',
            name='total_pages_fail',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditgroup2rulecategoryresult',
            name='total_pages_fail',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditgroup2rulescoperesult',
            name='total_pages_fail',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditgroup2guidelineresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2guidelineresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2result',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2result',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2rulecategoryresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2rulecategoryresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2ruleresult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2ruleresult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2rulescoperesult',
            name='implementation_pass_fail_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
        migrations.AlterField(
            model_name='auditgroup2rulescoperesult',
            name='implementation_score',
            field=models.DecimalField(decimal_places=1, default=-1, max_digits=4),
        ),
    ]
