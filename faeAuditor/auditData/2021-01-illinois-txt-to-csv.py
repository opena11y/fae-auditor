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
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

from string import capwords


sys.path.append(os.path.abspath('..'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fae_audit.settings')

class SubGroup:

  def __init__(self, subGroup):

    self.slug   = subGroup
    self.abbrev = makeAbbrev(subGroup)
    self.title  = makeTitle(subGroup)

class Group:

  def __init__(self, group):

    self.slug   = group
    self.abbrev = makeAbbrev(group)
    self.title  = makeTitle(group)
    self.subGroups = []

  def addSubGroup(self, subGroup):

    for sg in self.subGroups:
      if sg.slug == subGroup:
        return sg

    sg = SubGroup(subGroup)
    self.subGroups.append(sg)
    return sg

class Groups:

  def __init__(self):

    self.groups = []
    self.depth    = 3
    self.maxPages = 400

  def addGroup(self, group, subGroup):

    for g in self.groups:
      if g.slug == group:
        if subGroup:
          sg = g.addSubGroup(subGroup)
          return subGroup.title
        else:
          return "None"

    g = Group(group)
    self.groups.append(g)
    if subGroup:
      sg = g.addSubGroup(subGroup)
      return sg.title
    else:
      return "None"

class Domain:

  def __init__(self, g1, g2, g3, u):

    self.group1 = g1
    self.group2 = g2
    self.group3 = g3
    self.url    = u.strip('\n\t')


def cleanTitle(title):

  def checkForSeparator(s, separator):
    return s.find(separator) >= 0

  def getBestTitle(s, separator):
    try:
      parts = s.split(separator)
      s = parts[0].strip()

      if s.find('Home') >= 0 and len(parts) > 1:
        s = parts[1]

    except:
      s = "no usefull title"

    return s.strip()


  title = title.strip()

  if checkForSeparator(title, '|'):
    title = getBestTitle(title, '|')
  else:
    if checkForSeparator(title, '::'):
      title = getBestTitle(title, '::')
    else:
      if checkForSeparator(title, '-'):
        title = getBestTitle(title, '-')

  title = title.replace('&amp;', 'and')
  title = title.replace('&#039', '\'')
  title = title.replace('&#8211', '')
  title = title.replace('\\xc2\\xae', '')
  title = title.replace('\\xe2\\x80\\x93', '')
  title = title.replace('\\xe2\\x80\\x99', '\'')

  title = title.replace('\\n', '')
  title = title.replace('\\r', '')
  title = title.replace('\\t', '')
  title = title.replace('          ', ' ')
  title = title.replace('         ', ' ')
  title = title.replace('        ', ' ')
  title = title.replace('       ', ' ')
  title = title.replace('      ', ' ')
  title = title.replace('     ', ' ')
  title = title.replace('    ', ' ')
  title = title.replace('   ', ' ')
  title = title.replace('  ', ' ')

  return title.strip()

def makeAbbrev(s):

  s1 = s

  if s == 'disability':
    s1 = 'DRES'

  if s != s1:
    return s1

  s = s.replace('_', ' ')
  words = s.split(' ')

  title = []

  for w in words:

    if w == 'and' or w == 'of':
      continue

    else:

      if len(w) < 4 and w != 'la' and w != 'old' and w != 'new' and w != 'ole' and w != 'rio' and w != 'san' and w != 'st.':
        w = w.upper()
      else:
        w = w.capitalize()

      title.append(w)

  return ' '.join(title)


def makeTitle(s):

  if s == 'aces':
    s = 'Agriculture, Consumer and Enivronmental Sciences'

  if s == 'admin':
    s = 'Administration'

  if s == 'ahs':
    s = 'Applied Health Sciences'

  if s == 'architech':
    s = 'Architecture'

  if s == 'athletics':
    s = 'Intercollegiate Athletics'

  if s == 'business':
    s = 'College of Business'

  if s == 'center':
    s = 'Research Centers'

  if s == 'education':
    s = 'College of Education'

  if s == 'engineering':
    s = 'College of Engineering'

  if s == 'faa':
    s = 'Fine and Applied Arts'

  if s == 'graduate':
    s = 'Graduate College'

  if s == 'ischool':
    s = 'School of Information Sciences'

  if s == 'las':
    s = 'Liberal Arts and Sciences'

  if s == 'library':
    s = 'Liberal Arts and Sciences'

  if s == 'law':
    s = 'Law School'

  if s == 'ler':
    s = 'School of Labor and Employment Relations'

  if s == 'media':
    s = 'College of Media'

  if s == 'medicine':
    s = 'College of Medicine'

  if s == 'oiir':
    s = 'Inclusion and Intercutural Relations'

  if s == 'other':
    s = 'Other Programs'

  if s == 'social':
    s = 'School of Social Work'

  if s == 'support':
    s = 'Support Units and Divisions'

  if s == 'techsrv':
    s = 'Technology Services'

  if s == 'vetmed':
    s = 'Support Units and Divisions'


  s = s.replace('_', ' ')
  words = s.split(' ')

  title = []

  for w in words:

    if w == 'and' or w == 'of' or w == 'at':
      title.append(w)
      continue

    else:

      if w == 'u':
        w = 'University of'


      if len(w) < 4 and w != 'old' and w != 'new' and w != 'ole' and w != 'rio' and w != 'san' and w != 'st.':
        w = w.upper()
      else:
        w = w.capitalize()

      title.append(w)

  return ' '.join(title)


def getDomain(s):

  url_parts    = s.split("//")
  domain =  url_parts[0] + "//"
  url_parts    = url_parts[1].split("/")
  domain_parts = url_parts[0].split(".")


  for p in domain_parts:
    if p != 'www':
      domain += p + "."

  domain = domain.rstrip(".")

  return domain

if len(sys.argv) < 2:
  print("python 2021-01-illinois-to-csv.py urls.txt")
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'r')
file_csv  = open(sys.argv[1].replace('txt', 'csv'), 'w')
file_json  = open(sys.argv[1].replace('txt', 'json'), 'w')

urls = []
domains    = []
error_urls = []

groups = Groups()

count = 0

for line in file_urls:
  line = line.strip()
  if line[0] == '#':
    print('continue')
    continue
  count += 1
  parts = line.split(' ')
  part_count = len(parts)

  if part_count == 4:
    d =  Domain(parts[0],parts[1],parts[2],parts[3])
  if part_count == 3:
    d =  Domain(parts[0],'',parts[1],parts[2])
  if part_count == 2:
    d =  Domain('', '', parts[0],parts[1])

  print(str(count) + ' [' + d.group1 + '][' + d.group2 + ']['  + d.group3 + ']: ' + str(d.url))

  dup = False
  # check if domain is unique
  for item in domains:
    if item.url == d.url:
      dup = True
      break

  if not dup:
    domains.append(d)

print('\n-------------\n')

for index, item in enumerate(domains):

  ctx                = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode    = ssl.CERT_NONE

  hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)' }

  if item.group3:
    title = groups.addGroup(item.group1, item.group2)
    title += ': ' + makeTitle(item.group3)
  else:
    if item.group2:
      title = groups.addGroup(item.group1, false)
      title += ': ' + makeTitle(item.group2);
    else:
      title = makeTitle(item.group1);

  # Get title from web page
  try:
    request  = Request(item.url, headers=hdr)

    try:
      response = urlopen(request, context=ctx)

      try:
        html = str(response.read())

        try:

          start = html.find("<title")
          if start < 0:
            start = html.find("<TITLE")

          end   = html.find("</title")
          if end < 0:
            end   = html.find("</TITLE")

          body  = html.find("<body")
          if body < 0:
            body   = html.find("<BODY")


          if start != -1 or body != -1:
            title = ""

            if start != -1 and end != -1:
              title = html[(start+7):end]
              if title:
                title = cleanTitle(title)
          else:
            print("\nError no title or body tag found: " + str(index) + ": " + item + "\n")
        except:
          print("\nTitle Parsing Error: " + str(index) + ": " + item.url + "\n")
          error_urls.append(item)
      except:
        print("\nReading HTML Error: " + str(index) + ": " + item.url + "\n")
        error_urls.append(item)
    except:
      print("\nResponse HTML Error: " + str(index) + ": " + item.url + "\n")
      error_urls.append(item)
  except HTTPError as e:
    print("\nHTTP Error: " + str(e.code) + " for " + str(index) + ": " + item.url + "\n")
    item.error = str(e.code)
    error_urls.append(item)
  except URLError as e:
    print("\nURL Error:  " + str(e.reason) + " for " + str(index) + ": " + item.url + "\n")
    item.error = str(e.reason)
    error_urls.append(item)

  line = '"","","","' + title + '","' + item.url + '","' + item.group1 + '","' + item.group2 + '","' + item.group3  + '"'
  print(str(index) + ": " + line)
  file_csv.write(line + "\n")


for index, item in enumerate(error_urls):
  line = '"ERROR ' + str(index) + '",' + item.url
  file_csv.write(line + "\n")

file_csv.close()

file_json.write ('{ "title"        : "2021 University of Illinois Colleges",\n')
file_json.write ('  "audit_slug"   : "illinois-websites",\n')
file_json.write ('  "depth"        : 4,\n')
file_json.write ('  "ruleset_id"   : "ARIA_STRICT",\n')
file_json.write ('  "wait_time"    : 90000,\n')
file_json.write ('  "max_pages"    : 600,\n')
file_json.write ('  "groups"       : [\n')

if len(groups.groups):
  file_json.write ('  {\n')
  file_json.write ('    "id"           : "units",\n')
  file_json.write ('    "title"        : "College or Unit",\n')
  file_json.write ('    "title_plural" : "Colleges and Units",\n')
  file_json.write ('    "members" : [\n')

  if len(groups.groups):
    for g in groups.groups:
      file_json.write ('       {\n')
      file_json.write ('        "slug" : "' + g.slug + '",\n')
      file_json.write ('        "title": "' + g.title + '",\n')
      file_json.write ('        "abbrev": "' + g.abbrev + '"\n')

      if g == groups.groups[-1]:
        file_json.write ('       }\n')
      else:
        file_json.write ('       },\n')

  file_json.write ('    ]\n')

  if len(groups.groups[0].subGroups):

    file_json.write ('  },\n')

    file_json.write ('  {\n')
    file_json.write ('    "id"           : "department",\n')
    file_json.write ('    "title"        : "Department or Unit",\n')
    file_json.write ('    "title_plural" : "Departments and Units",\n')
    file_json.write ('    "members" : [\n')

    for g in groups.groups:
      for sg in g.subGroups:
        file_json.write ('       {\n')
        file_json.write ('        "group": "'  + sg.slug   + '",\n')
        file_json.write ('        "slug": "'   + sg.slug   + '",\n')
        file_json.write ('        "title": "'  + sg.title  + '",\n')
        file_json.write ('        "abbrev": "' + sg.abbrev + '"\n')

        if sg == g.subGroups[-1] and g == groups.groups[-1]:
          file_json.write ('       }\n')
        else:
          file_json.write ('       },\n')

    file_json.write ('    ]\n')

file_json.write ('  }\n')
file_json.write ('  ]\n')
file_json.write ('}\n')
