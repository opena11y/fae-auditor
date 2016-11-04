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
import textile
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

from rulesets.models import Ruleset
  
def removeQuotes(rs):

  s = ""

  for c in rs:
    if c != '"' and c != "\n":
      s += c
      
  return s

def titleFromSlug(s):

  parts = s.split('_')

  title = ""
  for p in parts:
    if title == "":
      title = p.title()
    else:  
      title = title + " " + p.title()

  return title
  
def getDomain(s):

  url_parts    = s.split("//")  
  url_parts    = url_parts[1].split("/")
  domain_parts = url_parts[0].split(".")
  
  domain = ""
  
  for p in domain_parts:
    if p != 'www':
      domain += p + "."
      
  domain = domain.rstrip(".")
  
  return domain

audit = False

audit_group = False

audit_group2 = False

website_count = 0
  
def addWebsite(audit, title, url, groups):

  global website_count

  website_count += 1

  sd = getDomain(url)
  sd = sd.strip()
  slug = 'ws' + str(website_count)
  
  try:
    ws = Website.objects.get(audit=audit, url=url)
    print("  Updating Website: " + url)
    ws.title = title 
    ws.span_domains = sd
    ws.slug = slug

  except:
    ws = Website(audit=audit, url=url, span_sub_domains=sd, title=title, slug=slug)
    print("  Creating Website: " + url)  

  ws.save()
  
  if len(groups) > 0 and audit_group:
      slug = removeQuotes(groups[0].strip())
      print(str(audit_group))
      try:
        agi = AuditGroupItem.objects.get(group=audit_group, slug=slug)
        print("  Found Audit group Item: " + slug + " " + url)
      except:
        agi =  AuditGroupItem(group=audit_group, slug=slug, title=titleFromSlug(slug))
        print("  Creating Audit Group Item: " +  slug + " " + url)  
        agi.save()

      ws.group_item = agi
      ws.save()  
      
  if len(groups) > 1 and audit_group2:
      slug = removeQuotes(groups[1].strip())
      print(str(audit_group2))
      try:
        ag2i = AuditGroup2Item.objects.get(group2=audit_group2, group_item=agi, slug=slug)
        print("  Found Audit group Item: " + slug + " " + url)
      except:
        ag2i =  AuditGroup2Item(group2=audit_group2, group_item=agi, slug=slug, title=titleFromSlug(slug))
        print("  Creating Audit Group Item: " +  slug + " " + url)  
        ag2i.save()  
      
      ws.group2_item = ag2i
      ws.save()  

def addAuditGroup2(audit, data):
  global audit_group2

  try:
    audit_group2 = AuditGroup2.objects.get(audit=audit, slug=data['id'])
    print("  Updating Audit Group2: " + data['title'])
    audit_group2.title    = data['title']
   
  except ObjectDoesNotExist:  
    print("  Creating Audit Group2: " + data['title'])
    audit_group2 = AuditGroup2(audit=audit, title=data['title'], slug=data['id']) 

  print("  Saving Audit Group2: " + data['title'])
  audit_group2.save()

def addAuditGroup(audit, data):
  global audit_group

  try:
    audit_group = AuditGroup.objects.get(audit=audit, slug=data['id'])
    print("  Updating Audit Group: " + data['title'])
    audit_group.title    = data['title']
   
  except ObjectDoesNotExist:  
    print("  Creating Audit Group: " + data['title'])
    audit_group = AuditGroup(audit=audit, title=data['title'], slug=data['id']) 

  print("  Saving Audit Group: " + data['title'])
  audit_group.save()
  
def addAudit(data):

  try:
    audit = Audit.objects.get(title=data['title'])
    print("  Updating Audit: " + data['title'])
   
  except ObjectDoesNotExist:  
    print("  Creating Audit: " + data['title'])
    audit = Audit(title=data['title'], user=user) 
     
  audit.slug    = data['audit_slug']
  audit.depth   = data['depth']
  
  audit.ruleset   = Ruleset.objects.get(ruleset_id=data['ruleset_id'])
  audit.wait_time = data['wait_time']
  audit.save()

  groups = data['groups']
  print("  Groups: " + str(groups))

  try:

    if len(groups) > 0:
      print("Group: " + str(groups[0]))
      addAuditGroup(audit, groups[0])

    if len(groups) > 1:
      print("Group2: " + str(groups[1]))
      addAuditGroup2(audit, groups[1])

    print("Audit Group: " + str(audit_group))  
    print("Audit Group2: " + str(audit_group2))  

  except:
    print("No group information")

  return audit

# Get title and other information for the audit
 
user = User.objects.get(username='jongund')
date = time.strftime('%Y-%m-%d')

if len(sys.argv) < 2:
  print("python populate_websites_from_csv.py file1.json file2.csv")
  exit()
 
file_json = open(sys.argv[1], 'r')

audit_data = json.load(file_json)

audit = addAudit(audit_data)

if len(sys.argv) < 3:
  print("python populate_websites_from_csv.py file1.json file2.csv")
  exit()

# Read in the CSV of the urls

file_csv  = open(sys.argv[2], 'rU')

for line in file_csv:
  print('LINE: ' + line)
  parts = line.split('","')
  if len(parts) > 1:
    title  = removeQuotes(parts[0]).strip()
    url    = removeQuotes(parts[1]).strip()
    print(str(len(parts)) + " " + title + " " + url)
    addWebsite(audit, title, url, parts[2:])
  else:
    print("**** Error: " + line) 
