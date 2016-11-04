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

file: fae-util/test_save_website_reports.py

Author: Jon Gunderson

"""

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
import shutil
import json
import csv
import django

sys.path.append(os.path.abspath('..'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'faeAuditor.settings')
django.setup()


from save_website_results_sql import saveResultsToDjango

from reports.models import WebsiteResult

    
def main():

  message_flag = True

  ws_reports = WebsiteResult.objects.all()
  
  if len(ws_reports):
    ws_report = ws_reports[0]

    # Removed any previous database relationships
    ws_report.processed_urls.all().delete()
    ws_report.unprocessed_urls.all().delete()
    ws_report.filtered_urls.all().delete()
    ws_report.filtered_urls.all().delete()

    ws_report.ws_gl_results.all().delete()
    ws_report.ws_rc_results.all().delete()
    ws_report.ws_rs_results.all().delete()

    ws_report.page_all_results.all().delete()

    print("=======================")
    print("Saving Data: " + str(ws_report))
    saveResultsToDjango(ws_report)

          
if __name__ == "__main__":
  main()
