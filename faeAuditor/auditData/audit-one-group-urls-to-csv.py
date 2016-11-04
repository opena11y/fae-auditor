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
import urllib2

from string import capwords


sys.path.append(os.path.abspath('..'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fae_audit.settings')

class Domain:
  
  def __init__(self, g1, u):
  
    self.group1 = g1
    self.url    = u.strip()

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
  print "python audut-one-group-to-csv.py file1.txt file2.csv"
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'rU')
file_csv  = open(sys.argv[2], 'w')

domains    = []
error_urls = []

for line in file_urls:
  parts = line.split(' ')
  print(str(len(parts)))
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
 
  try: 
    response = urllib2.urlopen(item.url)
    html = response.read()
    html1 = html.lower()
    
    start = html1.find("<title")
    end   = html1.find("</title")
    body  = html1.find("<body")
    
    if start != -1 or body != -1:
      title = ""
    
      if start != -1 and end != -1: 
        title = html[(start+7):end]
        title = clean(title.strip())
      
      line = '"NO TITLE ' + str(index) + '","' + item.url  + '","' + item.group1 + '"'
      if title != "":  
        line = '"' + title + '","' + item.url + '","' + item.group1 + '"'
      
      print str(index) + ": " + line
    
      file_csv.write(line + "\n")
    else:    
      print "*** Error no title or body tag: " + str(index) + ": " + item  
  except:
    print "*** Error retriving: " + str(index) + ": " + item.url  
    error_urls.append(item)

for index, item in enumerate(error_urls):    
  line = '"ERROR ' + str(index) + '",' + item.url 
  file_csv.write(line + "\n")  

file_csv.close()
      