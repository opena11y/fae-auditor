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

def reset_group_items(group):

  for item in group:
    item.reset()

def main():

    audit_results = AuditResult.objects.all()

    for ar in audit_results:
        print('Recomputing audit result: ' + str(ar))

        ar.status = 'A'
        ar.save()

        ar.reset();
        reset_group_items(ar.audit_rs_results.all())
        reset_group_items(ar.audit_rc_results.all())
        reset_group_items(ar.audit_gl_results.all())
        reset_group_items(ar.audit_rule_results.all())


        if ar.group_results:
          print('  reseting group results... (' + str(len(ar.group_results.all())) + ')')
          if len(ar.group_results.all()):
            for agr in ar.group_results.all():
              print('     reseting a group result: ' + str(agr))
              agr.reset()
              reset_group_items(agr.group_rs_results.all())
              reset_group_items(agr.group_rc_results.all())
              reset_group_items(agr.group_gl_results.all())
              reset_group_items(agr.group_rule_results.all())

              if agr.group2_results:
                print('      reseting group 2 results... (' + str(len(agr.group2_results.all())) + ')')
                if len(agr.group2_results.all()):
                  for ag2r in agr.group2_results.all():
                    print('         reseting a group 2 result: ' + str(ag2r))
                    ag2r.reset()
                    reset_group_items(ag2r.group2_rs_results.all())
                    reset_group_items(ag2r.group2_rc_results.all())
                    reset_group_items(ag2r.group2_gl_results.all())
                    reset_group_items(ag2r.group2_rule_results.all())
                else:
                    print('      no group 2 results')

          else:
            print('  no group results')


        print('  computing audit results...')

        ar.compute_audit_results(True)


if __name__ == "__main__":
  main()
