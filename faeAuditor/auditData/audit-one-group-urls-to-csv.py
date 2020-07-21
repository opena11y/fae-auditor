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

class Domain:

  def __init__(self, g1, u):

    self.group1 = g1
    self.url    = u.strip()

def clean(s):
  s = s.replace('\\t', '')
  s = s.replace('\\r', '')
  s = s.replace('\\n', '')
  return "".join([i for i in s if 31 < ord(i) < 127])

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

if len(sys.argv) < 3:
  print("python audit-one-group-to-csv.py file1.txt file2.csv")
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'rU')
file_csv  = open(sys.argv[2], 'w')

domains    = []
error_urls = []

total = 0
for line in file_urls:
  total += 1
  parts = line.split(' ')
#  print('Line ' + str(total) + ': ' + line)
  if len(parts) == 2:

    d =  Domain(parts[0],parts[1])

    dup = False
    # check if domain is unique
    for item in domains:
      if item.url == d.url:
        dup = True
        break

    if not dup:
      domains.append(d)

for index, item in enumerate(domains):

  ctx                = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode    = ssl.CERT_NONE

  hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)' }

  title = ""

  try:
    request  = Request(item.url, headers=hdr)
    response = urlopen(request, context=ctx)

    try:
      html = str(response.read())

      try:
        html1 = html.lower()
        start = html1.find("<title")
        end   = html1.find("</title")
        body  = html1.find("<body")

        if start != -1 and end != -1:
          title = html[(start+7):end]
          title = clean(title.strip()).strip()

      except:
        print("Parsing Error: " + str(index) + ": " + item.url)
        error_urls.append(item)
    except:
      print("Read Error: " + str(index) + ": " + item.url)
      error_urls.append(item)
  except HTTPError as e:
    print("HTTP Error: " + str(e.code) + " for " + str(index) + ": " + item.url)
    item.error = str(e.code)
    error_urls.append(item)
  except URLError as e:
    print("URL Error:  " + str(e.reason) + " for " + str(index) + ": " + item.url)
    item.error = str(e.reason)
    error_urls.append(item)

  line = '"NO TITLE ' + str(index) + '","' + item.url  + '","' + item.group1 + '"'
  if title != "":
    line = '"' + title + '","' + item.url + '","' + item.group1 + '"'

  print(str(index) + ' of ' + str(total) + ': ' + line)

  file_csv.write(line + "\n")


for index, item in enumerate(error_urls):
  line = '"ERROR ' + str(index) + '",' + item.url + ' (' + item.error + ')'
  file_csv.write(line + "\n")

file_csv.close()

