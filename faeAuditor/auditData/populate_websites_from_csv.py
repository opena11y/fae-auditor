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

def addWebsite(audit, depth, max_pages, wait_time, title, url, groups):

  global website_count

  website_count += 1

  sd = getDomain(url)
  sd = sd.strip()
  slug = 'ws%04u' % (website_count,)

  try:
    ws = Website.objects.get(audit=audit, url=url)
    print("  Updating Website: " + url)
    ws.title        = title
    ws.span_domains = sd
    ws.slug         = slug
    ws.depth        = depth
    ws.max_pages    = max_pages
    ws.wait_time    = wait_time

  except:
    ws = Website(audit=audit, url=url, span_sub_domains=sd, title=title, slug=slug, depth=depth, max_pages=max_pages, wait_time=wait_time)
    print("  Creating Website: " + url)

  ws.save()

  if len(groups) > 0 and audit_group:
      slug = removeQuotes(groups[0].strip()).strip()
      print(str(audit_group))
      try:
        agi = AuditGroupItem.objects.get(group=audit_group, slug=slug)
        print("  Found Audit group Item: '" + slug + "' " + url)
        ws.group_item = agi
        ws.save()
      except:
        print("  ERROR: Cannot Find Group Item: " +  slug)


  if len(groups) > 1 and audit_group2:
      slug = removeQuotes(groups[1].strip()).strip()
      print(str(audit_group2))
      try:
        ag2i = AuditGroup2Item.objects.get(group2=audit_group2, group_item=agi, slug=slug)
        print("  Found Audit group Item: '" + slug + "' " + url)
        ws.group2_item = ag2i
        ws.save()
      except:
        print("  ERROR: Cannot Find Group2 Item: " +  slug)


def addAuditGroup2(audit, data):
  global audit_group2

  try:
    audit_group2 = AuditGroup2.objects.get(audit=audit, slug=data['id'])
    print("\n  Updating Audit Group2: " + data['title'])
    audit_group2.title        = data['title']
    audit_group2.title_plural = data['title_plural']

  except ObjectDoesNotExist:
    print("\n  Creating Audit Group2: " + data['title'])
    audit_group2 = AuditGroup2(audit=audit, title=data['title'], title_plural=data['title_plural'], slug=data['id'])

  print("  Saving Audit Group2: " + data['title'])
  audit_group2.save()

  print("\n  Members: " + str(len(data['members'])))

  for member in data['members']:
    print("\n      Member: " + member['slug'])
    print("       Title: " + member['title'])
    print("Abbreviation: " + member['abbrev'])
    print("       Group: " + member['group'])

    group_item = AuditGroupItem.objects.get(group__audit=audit, slug=member['group'])

    print("  Group Item: " + str(group_item))

    try:
      ag2i = AuditGroup2Item.objects.get(group2=audit_group2, slug=member['slug'])
      ag2i.title        = member['title']
      ag2i.abbreviation = member['abbrev']
      print("    Found Audit group Item: " + member['slug'] + " " + member['title'])
    except:
      print("    Creating Audit Group2 Item: " +  member['slug'] + " " + member['title'])
      ag2i =  AuditGroup2Item(group2=audit_group2, group_item=group_item, slug=member['slug'], title=member['title'], abbreviation=member['abbrev'])

    ag2i.save()


def addAuditGroup(audit, data):
  global audit_group


  try:
    audit_group = AuditGroup.objects.get(audit=audit, slug=data['id'])
    print("  Updating Audit Group: " + data['title'])
    audit_group.title        = data['title']
    audit_group.title_plural = data['title_plural']

  except ObjectDoesNotExist:
    print("  Creating Audit Group: " + data['title'])
    audit_group = AuditGroup(audit=audit, title=data['title'], title_plural=data['title_plural'], slug=data['id'])

  audit_group.save();

  print("  Saving Audit Group: " + data['title'])
  print("\n  Members: " + str(len(data['members'])))

  for member in data['members']:
    print("\n    Member: " + str(member['slug']))
    try:
      agi = AuditGroupItem.objects.get(group=audit_group, slug=member['slug'])
      agi.title        = member['title']
      agi.abbreviation = member['abbrev']
      print("    Found Audit group Item: " + member['slug'] + " " + member['title'])
    except:
      agi =  AuditGroupItem(group=audit_group, slug=member['slug'], title=member['title'], abbreviation=member['abbrev'])
      print("    Creating Audit Group Item: " +  member['slug'] + " " + member['title'])
    agi.save()


  audit_group.save()

def addAudit(data):

  try:
    audit = Audit.objects.get(slug=data['audit_slug'])
    print("  Updating Audit: " + data['title'])

  except ObjectDoesNotExist:
    print("  Creating Audit: " + data['title'])
    audit = Audit(slug=data['audit_slug'], title=data['title'], user=user)

  audit.depth     = data['depth']
  audit.max_pages = data['max_pages']

  audit.ruleset   = Ruleset.objects.get(ruleset_id=data['ruleset_id'])
  audit.wait_time = data['wait_time']
  audit.save()

  groups = data['groups']

  print("Groups: " + str(len(groups)))

  try:

    if len(groups) > 0:
      print("Group: " + str(groups[0]['title']))
      addAuditGroup(audit, groups[0])

    print("\n=== Audit Group: " + str(audit_group) + "===")

    if len(groups) > 1:
      print("Group2: " + str(groups[1]['title']))
      addAuditGroup2(audit, groups[1])

    print("\n=== Audit Group2: " + str(audit_group2) + "===")

  except:
    print("No group information")

  return audit

# Get title and other information for the audit

user = User.objects.get(username='jongund')
date = time.strftime('%Y-%m-%d')

if len(sys.argv) < 3:
  print("python populate_websites_from_csv.py file1.json file2.csv")
  exit()

file_json = open(sys.argv[1], 'r')

audit_data = json.load(file_json)

audit = addAudit(audit_data)

# Read in the CSV of the urls

file_csv  = open(sys.argv[2], 'rU')

for line in file_csv:
  print('\n----------------------------------\n')
  print('LINE: ' + line)
  parts = line.split('","')
  if len(parts) > 1:
    depth = removeQuotes(parts[0]).strip()
    if len(depth) == 0:
      depth = audit.depth

    max_pages = removeQuotes(parts[1]).strip()
    if len(max_pages) == 0:
      max_pages = audit.max_pages

    wait_time = removeQuotes(parts[2]).strip()
    if len(wait_time) == 0:
      wait_time = audit.wait_time

    title  = removeQuotes(parts[3]).strip()
    url    = removeQuotes(parts[4]).strip()
    if len(parts) > 5:
      parts[5] = removeQuotes(parts[5]).strip()
    if len(parts) > 6:
      parts[6] = removeQuotes(parts[6]).strip()
    if len(parts) > 7:
      parts[7] = removeQuotes(parts[7]).strip()
    print(str(parts[5:]) + " " + title + " " + url)
    addWebsite(audit, depth, max_pages, wait_time, title, url, parts[5:])
  else:
    print("**** Error: " + line)
