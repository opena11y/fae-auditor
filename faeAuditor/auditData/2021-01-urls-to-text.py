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

def isUnique(name):

  for n in names:
    if n == name:
      return False

  return True

def getName(s):

  name = 'noname'
  parts    = s.split("//")
  if len(parts) > 1:
    parts =  parts[1].split('.')

    name = parts[0]
    if name == 'www':
      name = parts[1]

    if not isUnique(name):
      n = len(parts)
      name = parts[n-1]
      parts = name.split('/')
      n = len(parts)
      name = parts[0]
      if not isUnique(name) and n > 1:
        name = parts[1]

      if not isUnique(name) and n > 2:
        name = parts[2]

      if not isUnique(name) and n > 3:
        name = parts[3]

      if not isUnique(name):
        name = 'noname'

    names.append(name)

  return name

print('[args]: ' + str(len(sys.argv)))
print('[args]: ' + sys.argv[0]);
print('[args]: ' + sys.argv[1]);
print('[args]: ' + sys.argv[2]);

if len(sys.argv) < 3:
  print("python 2021-01-urls-to-text.py file1.txt file2.txt")
  exit()

# Read in the list of the urls

file_urls = open(sys.argv[1], 'r')
file_text  = open(sys.argv[2], 'w')

names = []
count = 0

for line in file_urls:
  l = line.strip()
  print(l[0])
  if l[0] == '#':
    print('contirue')
    continue
  count += 1
  parts = l.split(' ')
  n =  getName(parts[1])
#  print('\n[COUNT]: ' + str(count))
#  print('[LINE]: ' + l)
#  print('[NAME]: ' + n)
  l1 = parts[0] + ' ' + n + ' ' + parts[1]
  file_text.write(l1 + '\n')


file_text.close()
