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

file: fae-util/process_evaluation_requests.py

Author: Jon Gunderson

"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
import sys
import os
import string
import glob
import getopt

import optparse
import subprocess
import shlex
import time
import getopt
import shutil
import json
import csv
import urllib

import cmd
import django

import threading

fp = os.path.realpath(__file__)
path, filename = os.path.split(fp)
os.environ['FAE_HOME'] = path

fae_util_path = path

faeAuditor_path = path.split('/fae-util')[0]
sys.path.append(faeAuditor_path)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'faeAuditor.settings')
django.setup()

from django.conf import settings

from faeAuditor.settings import APP_DIR
from faeAuditor.settings import PROCESSING_THREADS

from django.db                 import models
from websiteResults.models     import WebsiteResult
from auditGroup2Results.models import AuditGroup2Result
from auditGroupResults.models  import AuditGroupResult
from auditResults.models       import AuditResult

from save_website_results_sql import saveResultsToDjango

DEBUG=True
INFO=True

log = open(os.path.join(APP_DIR + 'logs/process-evaluation.log'), 'w')

print(str(log))

def debug(s):
  if DEBUG and log:
    log.write('[PROC_EVAL_REQ][DEBUG]: ' + str(s) + '\n')
    log.flush()

def info(s):
  if INFO and log:
    try: 
      log.write('[PROC_EVAL_REQ][INFO]: ' + str(s) + '\n')
      log.flush()
      print('[PROC_EVAL_REQ][INFO]: ' + str(s))
    except:
      log.write('[PROC_EVAL_REQ][INFO]: error in string "s" \n')
      log.flush()
      print('[PROC_EVAL_REQ][INFO]: error in string "s" \n')
      

def error(s):
  if log:
    try:
      log.write('[PROC_EVAL_REQ][**ERROR]: ' + str(s) + '\n')
      log.flush()
    except:
      log.write('[PROC_EVAL_REQ][**ERROR]: error in string "s" \n')
      log.flush()
      

def init_oaa_script_file():
  f = open(fae_util_path + '/openajax_a11y/scripts.txt', 'w')
  f.write(fae_util_path + '/openajax_a11y/oaa_a11y_evaluation.js\n')
  f.write(fae_util_path + '/openajax_a11y/oaa_a11y_rules.js\n')
  f.write(fae_util_path + '/openajax_a11y/oaa_a11y_rulesets.js\n')
  f.close()


def init_audit_result(audit_result):

    def get_audit_group_result(group_item):
      print("[AudtResult][init_results][get_audit_group_result](self): " + str(self))
      print("[AudtResult][init_results][get_audit_group_result](group_item): " + str(group_item))

      try:
        print("[AudtResult][init_results][get_audit_group_result]: A")
        agr = AuditGroupResult.objects.get(audit_result=self, group_item=group_item)
        print("[AudtResult][init_results][get_audit_group_result]: B")
      except:  
        print("[AudtResult][init_results][get_audit_group_result]: C")
        agr = AuditGroupResult(audit_result=self, group_item=group_item)
        print("[AudtResult][init_results][get_audit_group_result]: D")
        agr.save()
        print("[AudtResult][init_results][get_audit_group_result]: E" )

      return agr  

    def get_audit_group2_result(group_result, group2_item):

      try:
        ag2r = AuditGroup2Result.objects.get(group_result=group_results, group2_item=group2_item)
      except:  
        ag2r = AuditGroup2Result(group_result=gr, group_item=g)
        ag2r.save()

      return ag2r  



    audit = audit_result.audit

    print("[init_audit_results]: " + str(audit))
  
    if audit:

      try:

        for ws in audit.websites.all():

          print("[AudtResult][init_results] ------------- ")
          print("[AudtResult][init_results]: " + str(ws))
          print("[AudtResult][init_results]: " + str(ws.group_item))
          print("[AudtResult][init_results]: " + str(ws.group2_item))

          if ws.group_item:
            print("[AudtResult][init_results]: A")
            agr = get_audit_group_result(ws.group_item)
            print("[AudtResult][init_results]: B")

            if ws.group2_item:
              print("[AudtResult][init_results]: C")
              ag2r = get_audit_group2_result(agr, ws.group2_item)
              print("[AudtResult][init_results]: D")

              wsr = websiteResult(audit_result=self, group_result=agr, group2_result=ag2r)
              print("[AudtResult][init_results]: E")
            else:
              print("[AudtResult][init_results]: F")
              wsr = websiteResult(audit_result=self, group_result=agr)
              print("[AudtResult][init_results]: G")

          else:    
            print("[AudtResult][init_results]: H")
            wsr = websiteResult(audit_result=self)
            print("[AudtResult][init_results]: I")
          
          print("[AudtResult][init_results]: " + str(wsr))

          wsr.save()    

      except:
        pass    


def initWebsiteResult(ws_report):

  data_dir       = ws_report.data_directory 
  data_prop_file = ws_report.data_property_file
  data_auth_file = ws_report.data_authorization_file
  data_urls_file = ws_report.data_multiple_urls_file
  
  if os.path.exists(data_dir):
     shutil.rmtree(data_dir)
          
  os.makedirs(data_dir)
          
  file_prop = open(data_prop_file, 'w')

  if len(data_urls_file) > 0:  
    file_prop.write("multipleUrls=" + data_urls_file + '\n')
  else:    
    file_prop.write("url=" + ws_report.url + '\n')

#  if len(data_auth_file) > 0:  
#    file_prop.write("authorization=" +  data_auth_file + '\n')     
  
  file_prop.write('recommendedRules=true\n');
  
  file_prop.write('depth='   + str(ws_report.depth) + '\n')
  file_prop.write('ruleset=' + ws_report.ruleset.ruleset_id + '\n')
  if ws_report.max_pages > 0:
    file_prop.write('maxPages=' + str(ws_report.max_pages) + '\n')

  file_prop.write('wait='    + str(ws_report.wait_time) + '\n')

  file_prop.write("spanDomains="    + ws_report.span_sub_domains    + '\n') 
  file_prop.write("excludeDomains=" + ws_report.exclude_sub_domains + '\n') 
  file_prop.write("includeDomains=" + ws_report.include_domains     + '\n')

  file_prop.write("outputDirectory=" + ws_report.data_directory + '/data' + '\n')

  file_prop.write("browserVersion=" + ws_report.browser_emulation   + '\n')

  file_prop.write("scripts=" + fae_util_path + "/openajax_a11y/scripts.txt\n")
  file_prop.write("exportFunction=toJSON\n")
  file_prop.write("exportExtension=json\n")
  file_prop.write("exportOption=true\n")

  file_prop.close()
  
  if len(data_auth_file) > 0:  
    file_auth = open(data_auth_file, 'w')
    file_auth.write('<?xml version="1.0" encoding="UTF-8"?>' + '\n')
    file_auth.write('<authorizations>' + '\n') 
    file_auth.write(ws_report.authorization.replace('\r', ''))    
    file_auth.write('</authorizations>' + '\n') 
    file_auth.close()

  if len(data_urls_file) > 0:  
    file_ws_urls = open(data_urls_file, 'w')
    for ws_url in ws_report.ws_eval_urls.all():
      if ws_url.valid:
        file_ws_urls.write(ws_url.url + '\n')    
      
    file_ws_urls.close()

  return

def analyzeWebsiteResult(ws_report, log):

  def countResultFiles(dir):
    fname = dir + "/processed_urls.csv"
    try:
      with open(fname) as f:
        return len(f.readlines())
      return 0      
    except:
      error("Error opening: " + fname)
      return 0    

  start = time.time()

  cmd = []
  cmd.append(settings.APP_DIR + 'faeAuditor/fae-util/run')

  cmd.append('-c')
  cmd.append(ws_report.data_property_file)

  if len(ws_report.data_authorization_file):
    cmd.append('-a')
    cmd.append(ws_report.data_authorization_file)

  proc = subprocess.call(cmd, stdout=log)      
        
  page_count = countResultFiles(ws_report.data_directory + '/data')

  ave_time = "{:10.4f}".format(time.time()-start) + " seconds (0 pages)"
  if page_count > 0:
    if page_count == 1:
      ave_time = "{:10.4f}".format(time.time()-start) + " seconds/page (1 page)"
    else:  
      ave_time = "{:10.4f}".format((time.time()-start)/page_count) + " seconds/page (" + str(page_count) + " pages)"
  
  info("  Pages analyzed: " + str(page_count))
  info('Average processing time per page: ' + ave_time) 

class faeUtilThread(threading.Thread):

    def __init__(self, ws_report):
      threading.Thread.__init__(self)

      self.ws_report = ws_report
      info("=======================")
      info("Initializing report: " + self.ws_report.title)
      info("           log file: " + str(self.ws_report.log_file))
      self.ws_report.set_status_initialized()
      initWebsiteResult(self.ws_report)

    def run(self):

      log = open(self.ws_report.log_file, 'w')

      info("Analyze website: " + self.ws_report.title)
      self.ws_report.set_status_analyzing()
      analyzeWebsiteResult(self.ws_report, log)

      info("Saving Data: " + self.ws_report.title)
      self.ws_report.set_status_saving()
      saveResultsToDjango(self.ws_report, log)

      log.close()


def main(argv):

  message_flag = True

  init_oaa_script_file()

  loop = True

  while loop:  

    audit_result = AuditResult.objects.filter(status="-").first()

    if audit_result:
      init_audit_result(audit_result)

    website_results = WebsiteResult.objects.filter(status="-")

    init_count = len(website_results)

    ws_analyzing = WebsiteResult.objects.filter(status="A")
    ws_saving    = WebsiteResult.objects.filter(status="S")

    processing_count = len(ws_analyzing) + len(ws_saving)

    if init_count and processing_count <= PROCESSING_THREADS:
      ws_report = ws_reports[0]

      # if no arguements use threading
      if len(argv) == 0:
        thread = faeUtilThread(ws_report)
        thread.start()
      else:
        info("=======================")
        info("Initializing report: " + ws_report.title)
        info("           log file: " + str(ws_report.log_file))
        ws_report.set_status_initialized()
        initWebsiteResult(ws_report)

        log = open(ws_report.log_file, 'w')

        info("Analyze website: " + ws_report.title)
        ws_report.set_status_analyzing()
        analyzeWebsiteResult(ws_report, log)

        info("Saving Data: " + ws_report.title)
        ws_report.set_status_saving()
        saveResultsToDjango(ws_report, log)

        log.close()         

      message_flag = True
    else:
      if message_flag:
        info("No report requests pending... ")
        info("Reports waiting: " + str(init_count))
        info("Reports running: " + str(processing_count))
        message_flag = False

      time.sleep(1)

    if len(argv):
      loop = False  
          
if __name__ == "__main__":
  main(sys.argv[1:])
