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
import urllib.request
import urllib.error

from string import capwords


sys.path.append(os.path.abspath('..'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fae_audit.settings')

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

print('[args]: ' + str(len(sys.argv)))
print('[args]: ' + sys.argv[0]);
print('[args]: ' + sys.argv[1]);
print('[args]: ' + sys.argv[2]);

if len(sys.argv) < 3:
  print("python create_scv_from_urls.py file1.txt file2.csv")
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'r')
file_csv  = open(sys.argv[2], 'w')

domains = []
error_urls = []

for line in file_urls:
  d =  getDomain(line)

  if d.find("illinois.edu") != -1:

    dup = False
    # check if domain is unique
    for item in domains:
      if item == d:
        dup = True
        break

    if not dup:
      domains.append(d)

for index, item in enumerate(domains):

# for testing
#  if index > 10:
#    break

  try:
    response = urllib.request.urlopen(item)
    html = str(response.read())
    html1 = html.lower()

    start = html1.find("<title")
    end   = html1.find("</title")
    body  = html1.find("<body")

    if start != -1 or body != -1:
      title = ""

      if start != -1 and end != -1:
        title = html[(start+7):end]
        title = title.strip()

      line = '"NO TITLE ' + str(index) + '",' + item
      if title != "":
        line = '"' + title + '",' + item

      print(str(index) + ": " + line)

      file_csv.write(line + "\n")
    else:
      print("*** Error no title or body tag: " + str(index) + ": " + item)
  except urllib.error.URLError as e:
    print("*** Error retriving: " + str(index) + ": " + item + ' ' + e)
    error_urls.append(item)

for index, item in enumerate(error_urls):
  line = '"ERROR ' + str(index) + '",' + item
  file_csv.write(line + "\n")

file_csv.close()
