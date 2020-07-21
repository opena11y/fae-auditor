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

class University:

  def __init__(self, univ):

    self.slug   = univ
    self.abbrev = makeAbbrev(univ)
    self.title  = makeTitle(univ)

class Conference:

  def __init__(self, conf):

    self.slug   = conf
    self.abbrev = makeAbbrev(conf)
    self.title  = makeTitle(conf)
    self.universities = []

  def addUniversity(self, univ):

    for u in self.universities:
      if u.slug == univ:
        return u

    u = University(univ)
    self.universities.append(u)
    return u

class Conferences:

  def __init__(self):

    self.conferences = []
    self.depth    = 2
    self.maxPages = 400

  def addConferenceUniversity(self, conf, univ):

    for c in self.conferences:
      if c.slug == conf:
        u = c.addUniversity(univ)
        return u.title

    c = Conference(conf)
    self.conferences.append(c)
    u = c.addUniversity(univ)
    return u.title

class Domain:

  def __init__(self, g1, g2, g3, u):

    self.group1 = g1
    self.group2 = g2
    self.group3 = g3
    self.url    = u.strip('\n\t')

def clean(s):
  s1 = ""

  s = s.replace('\\n', '')
  s = s.replace('\\r', '')
  s = s.replace('\\t', '')
  s = s.replace('          ', ' ')
  s = s.replace('         ', ' ')
  s = s.replace('        ', ' ')
  s = s.replace('       ', ' ')
  s = s.replace('      ', ' ')
  s = s.replace('     ', ' ')
  s = s.replace('    ', ' ')
  s = s.replace('   ', ' ')
  s = s.replace('  ', ' ')

  return s.strip()

def makeAbbrev(s):

  s1 = s

  if s == 'acc':
    s1 = 'ACC'

  if s == 'atlantic10':
    s1 = 'Atl10'

  if s == 'big10':
    s1 = 'Big10'

  if s == 'big12':
    s1 = 'Big12'

  if s == 'bigwest':
    s1 = 'BigWest'

  if s == 'bigeast':
    s1 = 'BigEast'

  if s == 'conferenceusa':
    s1 = 'ConfUSA'

  if s == 'missourivalley':
    s1 = 'MoValley'

  if s == 'pac12':
    s1 = 'Pac12'

  if s == 'u_mo_kc':
    s1 = 'MoKC'

  if s == 'u_tx_rio_grande':
    s1 = 'TexRG'

  if s == 'notre_dame':
    s1 = 'ND'

  if s == 'seattle':
    s1 = 'SeaU'

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

  if s == 'acc':
    s = 'Atlantic Coast'

  if s == 'atlantic10':
    s = 'Atlantic 10'

  if s == 'big10':
    s = 'Big Ten'

  if s == 'big12':
    s = 'Big 12'

  if s == 'bigwest':
    s = 'Big West'

  if s == 'bigeast':
    s = 'Big East'

  if s == 'conferenceusa':
    s = 'Conference USA'

  if s == 'missourivalley':
    s = 'Missouri Valley'

  if s == 'pac12':
    s = 'Pacific 12'

  if s == 'sec':
    s = 'Southeast'

  if s == 'wac':
    s = 'Western Athletic'

  if s == 'fsu':
    s = 'Florida State'

  if s == 'uab':
    s = "Alabama at Birmingham"

  if s == 'utep':
    s = 'Texas at El Paso'

  if s == 'mit':
    s = 'Massachusetts Institute of Technology'

  if s == 'osu':
    s = 'The Ohio State University'

  if s == 'ole_miss':
    s = 'Mississippi'

  if s == 'psu':
    s = 'Penn State'

  if s == 'umich':
    s = 'Michigan'

  if s == 'msu':
    s = 'Michigan State'

  if s == 'usc':
    s = 'University of Southern California'

  if s == 'lsu':
    s = 'Louisiana State University'

  if s == 'tcu':
    s = 'Texas Christian University'

  if s == 'bc':
    s = 'Boston College'

  if s == 'u_mo_kc':
    s = 'Missouri at Kansas City'

  if s == 'u_tx_rio_grande':
    s = 'Texas Rio Grande'

  if s == 'seattle':
    s = 'Seattle University'


  s = s.replace('_', ' ')
  words = s.split(' ')

  title = []

  for w in words:

    if w == 'and' or w == 'of' or w == 'at':
      title.append(w)
      continue

    else:
      if w == 'st':
        w = 'st.'

      if w == 'cal':
        w = 'California'


      if w == 'tx':
        w = 'Texas'

      if w == 'u':
        w = 'University of'

      if w == 'kc':
        w = 'Kansas City'

      if w == 'mo':
        w = 'Missouri'

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
  print("python create_scv_from_urls.py filename.txt")
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'rU')
file_csv  = open(sys.argv[1].replace('txt', 'csv'), 'w')
file_json  = open(sys.argv[1].replace('txt', 'json'), 'w')

urls = []
domains    = []
error_urls = []

conferences = Conferences()

count = 0

for line in file_urls:
  parts = line.split(' ')
  if len(parts) > 3:

    index = 3
    while index < len(parts) and parts[index] == '':
      index = index + 1

    d =  Domain(parts[0],parts[1],parts[2],parts[index])
    count += 1
    print(str(count) + ": " + str(d.url))

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

  title = conferences.addConferenceUniversity(item.group1, item.group2)

  title += ': ' + makeTitle(item.group3);

  line = '"","","","' + title + '","' + item.url + '","' + item.group1 + '","' + item.group2 + '","' + item.group3  + '"'
  print(str(index) + ": " + line)
  file_csv.write(line + "\n")

  continue

  try:
    request  = Request(item.url, headers=hdr)
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
              title = clean(title)
        else:
          print("\nError no title or body tag found: " + str(index) + ": " + item + "\n")
      except:
        print("\nTitle Parsing Error: " + str(index) + ": " + item.url + "\n")
        error_urls.append(item)
    except:
      print("\nReading HTML Error: " + str(index) + ": " + item.url + "\n")
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

file_json.write ('{ "title"        : "2018 Basketball Conferences",\n')
file_json.write ('  "audit_slug"   : "2018-bb-conf",\n')
file_json.write ('  "depth"        : 2,\n')
file_json.write ('  "ruleset_id"   : "ARIA_STRICT",\n')
file_json.write ('  "wait_time"    : 90000,\n')
file_json.write ('  "max_pages"    : 200,\n')
file_json.write ('  "groups"       : [\n')
file_json.write ('  {\n')
file_json.write ('    "id"           : "conference",\n')
file_json.write ('    "title"        : "Conference",\n')
file_json.write ('    "title_plural" : "Conferences",\n')
file_json.write ('    "members" : [\n')

for c in conferences.conferences:
  file_json.write ('       {\n')
  file_json.write ('        "slug" : "' + c.slug + '",\n')
  file_json.write ('        "title": "' + c.title + '",\n')
  file_json.write ('        "abbrev": "' + c.abbrev + '"\n')

  if c == conferences.conferences[-1]:
    file_json.write ('       }\n')
  else:
    file_json.write ('       },\n')


file_json.write ('    ]\n')
file_json.write ('  },\n')

file_json.write ('  {\n')
file_json.write ('    "id"           : "university",\n')
file_json.write ('    "title"        : "University",\n')
file_json.write ('    "title_plural" : "Universities",\n')
file_json.write ('    "members" : [\n')

for c in conferences.conferences:
  for u in c.universities:
    file_json.write ('       {\n')
    file_json.write ('        "group": "'  + c.slug   + '",\n')
    file_json.write ('        "slug": "'   + u.slug   + '",\n')
    file_json.write ('        "title": "'  + u.title  + '",\n')
    file_json.write ('        "abbrev": "' + u.abbrev + '"\n')

    if u == c.universities[-1] and c == conferences.conferences[-1]:
      file_json.write ('       }\n')
    else:
      file_json.write ('       },\n')


file_json.write ('    ]\n')
file_json.write ('  }\n')
file_json.write ('  ]\n')
file_json.write ('}\n')
