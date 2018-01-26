# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2018-01-11 18:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auditResults', '0004_auto_20180110_1328'),
    ]

    operations = [
        migrations.AddField(
            model_name='auditguidelineresult',
            name='has_manual_checks',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='auditguidelineresult',
            name='implementation_pass_fail_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditguidelineresult',
            name='implementation_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditguidelineresult',
            name='total_pages',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditresult',
            name='has_manual_checks',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='auditresult',
            name='implementation_pass_fail_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditresult',
            name='implementation_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditrulecategoryresult',
            name='has_manual_checks',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='auditrulecategoryresult',
            name='implementation_pass_fail_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditrulecategoryresult',
            name='implementation_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditrulecategoryresult',
            name='total_pages',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditrulescoperesult',
            name='has_manual_checks',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='auditrulescoperesult',
            name='implementation_pass_fail_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditrulescoperesult',
            name='implementation_summ',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='auditrulescoperesult',
            name='total_pages',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditresult',
            name='status',
            field=models.CharField(choices=[('-', 'Created'), ('I', 'Initalized'), ('A', 'Analyzing'), ('S', 'saving Group Results'), ('C', 'Complete'), ('E', 'Error'), ('D', 'Marked for deletion')], default='-', max_length=10, verbose_name='Status'),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_hidden',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_mc_failed',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_mc_identified',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_mc_na',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_mc_passed',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_passed',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_violation',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='elements_warning',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='auditruleresult',
            name='pages_with_hidden_content',
            field=models.BigIntegerField(default=0),
        ),
    ]