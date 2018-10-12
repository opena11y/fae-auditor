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

  def __init__(self, g1, g2, g3, u):

    self.group1 = g1
    self.group2 = g2
    self.group3 = g3
    self.url    = u.strip('\n\t')

def clean(s):
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
  print("python create_scv_from_urls.py file1.txt file2.csv")
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'rU')
file_csv  = open(sys.argv[2], 'w')

urls = []
domains    = []
error_urls = []

for line in file_urls:
  parts = line.split(' ')
  if len(parts) > 3:

    index = 3
    while index < len(parts) and parts[index] == '':
      index = index + 1

    d =  Domain(parts[0],parts[1],parts[2],parts[index])
    print(str(d.url))

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

  title = item.group2.capitalize() + ': ' + item.group3.capitalize()

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
              print('TITLE: ' + str(title) + ' ' + str(start) + ' ' + str(end))
              title = clean(title.strip())
        else:
          print("*** Error no title or body tag found: " + str(index) + ": " + item)
      except:
        print("Title Parsing Error: " + str(index) + ": " + item.url)
        error_urls.append(item)
    except:
      print("Reading HTML Error: " + str(index) + ": " + item.url)
      error_urls.append(item)
  except HTTPError as e:
    print("HTTP Error: " + str(e.code) + " for " + str(index) + ": " + item.url)
    item.error = str(e.code)
    error_urls.append(item)
  except URLError as e:
    print("URL Error:  " + str(e.reason) + " for " + str(index) + ": " + item.url)
    item.error = str(e.reason)
    error_urls.append(item)

  line = '"' + title + '","' + item.url + '","' + item.group1 + '","' + item.group2 + '","' + item.group3  + '"'
  print(str(index) + ": " + line)
  file_csv.write(line + "\n")


#  except:
#    print("*** Error retrieving: " + str(index) + ": " + item.url)
#    error_urls.append(item)

for index, item in enumerate(error_urls):
  line = '"ERROR ' + str(index) + '",' + item.url
  file_csv.write(line + "\n")

file_csv.close()

