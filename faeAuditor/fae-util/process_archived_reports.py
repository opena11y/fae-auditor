"""
Copyright 2014-2016 University of Illinois

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

file: fae-util/process_archived_reports.py

Author: Jon Gunderson

"""

from __future__ import print_function
from __future__ import absolute_import
import sys
import os
import string
import glob

import optparse
import shlex
import time
import getopt
import shutil
import datetime

import django

fp = os.path.realpath(__file__)
path, filename = os.path.split(fp)
os.environ['FAE_HOME'] = path

fae_util_path = path

faeAuditor_path = path.split('/fae-util')[0]

# print("[faeAuditor_path]"+ str(faeAuditor_path))

sys.path.append(faeAuditor_path)

# print("PATH="+ str(sys.path))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'faeAuditor.settings')
django.setup()

from django.conf import settings

from faeAuditor.settings import APP_DIR
from faeAuditor.settings import PROCESSING_THREADS

from django.db       import models
from reports.models  import WebsiteResult
from django.contrib.auth.models import User

from django.core.exceptions     import ObjectDoesNotExist

from userProfiles.models import UserProfile

DEBUG=True
INFO=True
ERROR=True

log = open(os.path.join(APP_DIR + 'logs/archived-reports.log'), 'w')

def debug(s):
  if DEBUG and log:
    log.write("[ARCHIVED REPORTS][debug]: " + str(s) + "\n")
    log.flush()  
    print("[ARCHIVED REPORTS][debug]: " + str(s) + "\n")


def info(s):
  if INFO and log:
    log.write("[ARCHIVED REPORTS][info]: " + str(s) + "\n")
    log.flush()
    if DEBUG:
      print("[ARCHIVED REPORTS][info]: " + str(s) + "\n")

def error(s):
  if ERROR and log:
    log.write("[ARCHIVED REPORTS][**ERROR]: " + str(s) + "\n")
    log.flush()
    if DEBUG:
      print("[ARCHIVED REPORTS][**ERROR]: " + str(s) + "\n")


def archive_reports():

  info('Processing archived reports: ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M") )

  # Delete reports with errors
  error_reports = WebsiteResult.objects.filter(status='E')

  for r in error_reports:
    try:
      info("  Deleting:" + r.title)
      r.delete()
    except:
      error("Error deleting (error): " + str(r))  

  # Delete reports with marked for deletion
  reports_marked_for_deletion = WebsiteResult.objects.filter(status='D')

  for r in reports_marked_for_deletion:
    try:
      info("  Summary (marked):" + r.title)
      r.set_status_summary()
    except:
      error("Error summary (marked): " + str(r))  

  for user_profile in UserProfile.objects.all():
    
    if user_profile.user.username == 'anonymous':
      continue
    else:
      [reports, other_reports] = user_profile.get_active_reports()

    for r in other_reports:
      try:
        info("  Summary (other):" + r.title)
        r.set_status_summary()
      except:
        error("Error summary (other): " + str(r))          

if __name__ == "__main__":
  archive_reports()
