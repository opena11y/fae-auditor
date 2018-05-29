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

file: fae-util/test_save_website_results.py

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


from auditResults.models import AuditResult

from faeAuditor.settings import APP_DIR

# log = open(os.path.join(APP_DIR + 'logs/process-evaluation.log'), 'w')

log = sys.stdout

def main():

    audit_results = AuditResult.objects.all()

    for ar in audit_results:
        ar.delete()

    for ar in audit_results:
        ar.status = 'A'
        ar.save()

        print('Procssing audit result: ' + str(ar))

        try:
          print('  deleting group1 results...')
          if ar.group_results:
            for agr in ar.group_results.all():

              agr.group_rs_results.all().delete()
              agr.group_rc_results.all().delete()
              agr.group_gl_results.all().delete()
              agr.group_rule_results.all().delete()
        except:
            print('  no group results')

        try:
          if ar.group2_results:
            print('  deleting group2 results...')
            for ag2r in ar.group2_results.all():

              ag2r.group2_rs_results.all().delete()
              ag2r.group2_rc_results.all().delete()
              ag2r.group2_gl_results.all().delete()
              ag2r.group2_rule_results.all().delete()
        except:
            print('  no group2 results')

            print('  deleting audit results...')
        ar.audit_rs_results.all().delete()
        ar.audit_rc_results.all().delete()
        ar.audit_gl_results.all().delete()
        ar.audit_rule_results.all().delete()

        ar.check_if_audit_result_complete()


if __name__ == "__main__":
  main()
