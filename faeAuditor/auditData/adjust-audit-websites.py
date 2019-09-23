from __future__ import print_function
from __future__ import absolute_import

import sys
import os
import string
import glob

import optparse
import subprocess
import shlex
import time
import getopt

import json
from string import capwords

import django
from django.core.exceptions import ObjectDoesNotExist

fp = os.path.realpath(__file__)
path, filename = os.path.split(fp)

fae2_path = path.split('/auditData')[0]
sys.path.append(fae2_path)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'faeAuditor.settings')
from django.conf import settings

django.setup()

"""This file is for populating the database with markup information
I empty it. Run as a standalone script!"""

from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User

from audits.models import Audit
from audits.models import AuditGroup
from audits.models import AuditGroupItem
from audits.models import AuditGroup2
from audits.models import AuditGroup2Item
from audits.models import Website

from auditResults.models import AuditResult
from auditResults.models import AuditGroupResult
from auditResults.models import AuditGroup2Result

from rulesets.models import Ruleset


if len(sys.argv) < 2:
  print("python .py id")
  exit()

ar = AuditResult.objects.get(id=sys.argv[1])


print('\n\n')
count_zero = 0
for wsr in ar.ws_results.all():
  if wsr.page_count == 0:
    count_zero += 1
    ws = ar.audit.websites.get(slug=wsr.slug)
    ws.url = ws.url.replace('http:', 'https:').replace('www.','')
    ws.save()
    print(str(ws.id) + ": " + ws.title + ' ' + str(wsr.page_count) + ' ' + ws.url)

print('\n\n')
count_low = 0
for wsr in ar.ws_results.all():
  if wsr.page_count < 3 and wsr.page_count != 0:
    count_low += 1
    ws = ar.audit.websites.get(slug=wsr.slug)
    ws.url = ws.url.replace('http:', 'https:').replace('www.', '')
    ws.follow = 2
    ws.save()
    print(str(ws.id) + ": " + ws.title + ' ' + str(wsr.page_count) + ' ' + ws.url + ' ' + str(ws.follow) + ' ' + ws.span_sub_domains)

print('\nWebsites with Zero pages: ' + str(count_zero))
print('\nWebsites with a low number of pages: ' + str(count_low))

