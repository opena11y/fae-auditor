"""
Copyright 2014-2018 University of Illinois

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

file: fae-util/save_website_results.py

Author: Jon Gunderson

"""

from __future__ import division
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
import shutil
import json
import csv
import re
import datetime

from os.path import join, getsize

import urllib

# sys.path.append(os.path.abspath('..'))

from django.utils.encoding  import iri_to_uri

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'faeAuditor.settings')

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

from django.conf import settings

from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User

from django.db       import models

from websiteResults.models  import WebsiteResult
from websiteResults.models  import ProcessedURL
from websiteResults.models  import FilteredURL
from websiteResults.models  import UnprocessedURL

from websiteResults.models import WebsiteRuleCategoryResult
from websiteResults.models import WebsiteGuidelineResult
from websiteResults.models import WebsiteRuleScopeResult
from websiteResults.models import WebsiteRuleResult

from pageResults.models import PageResult
from pageResults.models import PageRuleCategoryResult
from pageResults.models import PageGuidelineResult
from pageResults.models import PageRuleScopeResult
from pageResults.models import PageRuleResult

from wcag20.models         import Guideline
from ruleCategories.models import RuleCategory
from rules.models          import Rule
from rules.models          import RuleScope

from auditGroupResults.models   import AuditGroupResult
from auditGroup2Results.models  import AuditGroup2Result

from save_fae_util_information import processedUrlsToDatabase
from save_fae_util_information import unprocessedUrlsToDatabase
from save_fae_util_information import filteredUrlsToDatabase
from save_fae_util_information import statusToDatabase

from save_markup_information import PageMarkupInformation

from django.db import connection, transaction

class RULE_RESULT:
  UNDEFINED      = 0
  NOT_APPLICABLE = 1
  PASS           = 2
  MANUAL_CHECK   = 3
  WARNING        = 4
  VIOLATION      = 5

DEBUG=False
INFO=True
ERROR=True

log = False

def debug(s):
  if DEBUG and log:
#    log.write("[SAVE WEBSITE][debug  ]: " + str(s) + "\n")
#    log.flush()
    print("[SAVE WEBSITE][debug  ]: " + str(s) + "\n")


def info(s):
  if INFO and log:
    log.write("[SAVE WEBSITE][info   ]: " + str(s) + "\n")
    log.flush()
    if DEBUG:
      print("[SAVE WEBSITE][info   ]: " + str(s) + "\n")

def error(s):
  if DEBUG:
    print("[SAVE WEBSITE][**ERROR]: " + str(s) + "\n")
  else:
    if ERROR and log:
      log.write("[SAVE WEBSITE][**ERROR]: " + str(s) + "\n")
      log.flush()

# ---------------------------------------------------------------
#
# General utilities for module
#
# ---------------------------------------------------------------

def escapeSingleQuotes(str):
  str1 = str.replace("'", "''")
  return str1.replace("%", "XX_")

# ---------------------------------------------------------------
#
# Rule References
#
# ---------------------------------------------------------------

class RuleRef:

  def __init__(self, rule_id, rule):
    self.rule_id = rule_id
    self.rule    = rule

class RuleRefs:

  def __init__(self):
    self.rule_refs = []

    rules = Rule.objects.all()

    for r in rules:
      rr = RuleRef(r.rule_id, r)
      self.rule_refs.append(rr)

  def getRule(self, rule_id):
    for rr in self.rule_refs:
      if rr.rule_id == rule_id:
        return rr.rule

    return False

rule_refs = RuleRefs()

# ---------------------------------------------------------------
#
# Rule Category References
#
# ---------------------------------------------------------------

class RuleCategoryRef:

  def __init__(self, code, rc):
    self.rule_category_code = code
    self.rule_category      = rc

class RuleCategoryRefs:

  def __init__(self):
    self.rc_refs = []

    rule_categories = RuleCategory.objects.all()

    for rc in rule_categories:
      rcr = RuleCategoryRef(rc.rule_category_code, rc)
      self.rc_refs.append(rcr)

  def getRuleCategory(self, code):
    for rcr in self.rc_refs:
      if rcr.rule_category_code == code:
        return rcr.rule_category

    return False

rule_category_refs = RuleCategoryRefs()

# ---------------------------------------------------------------
#
# Guideline References
#
# ---------------------------------------------------------------

class GuidelineRef:

  def __init__(self, n, g):
    self.number    = n
    self.guideline = g

class GuidelineRefs:

  def __init__(self):
    self.guideline_refs = []

    guidelines = Guideline.objects.all()

    for g in guidelines:
      gr = GuidelineRef(g.number, g)
      self.guideline_refs.append(gr)

  def getGuideline(self, num):
    for gr in self.guideline_refs:
      if gr.number == num:
        return gr.guideline

    return False

guideline_refs = GuidelineRefs()

# ---------------------------------------------------------------
#
# Rule Scope References
#
# ---------------------------------------------------------------

class RuleScopeRef:

  def __init__(self, c, rs):
    self.rule_scope_code = c
    self.rule_scope      = rs

class RuleScopeRefs:

  def __init__(self):
    self.rs_refs = []

    rule_scopes = RuleScope.objects.all()

    for rs in rule_scopes:
      rsr = RuleScopeRef(rs.rule_scope_code, rs)
      self.rs_refs.append(rsr)

  def getRuleScope(self, code):
    for rsr in self.rs_refs:
      if rsr.rule_scope_code == code:
        return rsr.rule_scope

    return False


rule_scope_refs = RuleScopeRefs()

# ---------------------------------------------------------------
#
# DataResult (Abstract)
#
# ---------------------------------------------------------------

class DataResult(object):

  def __init__(self):

    self.result_value = RULE_RESULT.NOT_APPLICABLE

    self.implementation_pass_fail_score  = -1
    self.implementation_pass_fail_status = "U"

    self.implementation_score       = -1
    self.implementation_score_fail  = -1
    self.implementation_score_mc    = -1
    self.implementation_status      = "U"

    self.manual_check_status = "NC"

    self.cols = []
    self.values = []

  def addColumnValue(self,c,v):
#    debug("[DataResult][addColumnValue] " + c + " " + str(v))
    self.cols.append(c)
    self.values.append(v)

  def saveToDjango(self, table):

#    debug("[DataResult][saveToDjango] " + table + " " + str(len(self.cols)) + " " + str(len(self.values)))

    insert_str = "INSERT INTO \"" + table + "\" ( "
    for col in self.cols:
      insert_str += col + ", "
    insert_str += "result_value, "
    insert_str += "implementation_pass_fail_score, "
    insert_str += "implementation_pass_fail_status, "
    insert_str += "implementation_score, "
    insert_str += "implementation_score_fail, "
    insert_str += "implementation_score_mc, "
    insert_str += "implementation_status, "
    insert_str += "manual_check_status"
    insert_str += ") VALUES ( "
    for v in self.values:
      v = str(v)
#      debug("[DataResult][saveToDjango] " +  v + " " + str(v.isdigit()))
      if v.isdigit():
        insert_str += v + ", "
      else:
        insert_str += "'" + v + "', "
    insert_str +=  str(self.result_value) + ", "
    insert_str +=  str(self.implementation_pass_fail_score) + ", "
    insert_str +=  "'" + self.implementation_pass_fail_status + "', "
    insert_str +=  str(self.implementation_score) + ", "
    insert_str +=  str(self.implementation_score_fail) + ", "
    insert_str +=  str(self.implementation_score_mc) + ", "
    insert_str +=  "'" + self.implementation_status + "', "
    insert_str +=  "'" + self.manual_check_status + "'"
    insert_str +=  ")"

 #   debug("[DataResult][saveToDjango] " + insert_str)

    cursor = connection.cursor()
    try:
      cursor.execute(insert_str, [])
    except:
      error("[DataResult][saveToDjango] SQL insert error")
      error("[DataResult][saveToDjango] " + insert_str)



# ---------------------------------------------------------------
#
# DataRuleResult (Abstract)
#
# ---------------------------------------------------------------

class DataRuleResult(DataResult):

  def __init__(self):

    super(DataRuleResult,self).__init__()

    self.sql_id = False

    self.rules_na           = 0
    self.rules_passed       = 0
    self.rules_manual_check = 0
    self.rules_warning      = 0
    self.rules_violation    = 0

    self.rules_with_hidden_content    = 0

    self.rule_results = []

  def saveToDjango(self, table):

#    debug("[DataRuleResult][saveToDjango] " + table + " " + str(len(self.cols)) + " " + str(len(self.values)))

    self.addColumnValue('rules_na', self.rules_na)
    self.addColumnValue('rules_passed', self.rules_passed)
    self.addColumnValue('rules_manual_check', self.rules_manual_check)
    self.addColumnValue('rules_warning', self.rules_warning)
    self.addColumnValue('rules_violation', self.rules_violation)
    self.addColumnValue('rules_with_hidden_content', self.rules_with_hidden_content)

    super(DataRuleResult, self).saveToDjango(table)


  def __str__(self):
    return "ID: %6d V: %6d W: %6d MC: %6d P: %6d NA: %6d RV: %2d Score: %3d Status: %s " % (self.sql_id, self.rules_violation, self.rules_warning, self.rules_mc_indentified, self.rules_passed, self.rules_na, self.result_value, self.implementation_score, self.implementation_status)

  def addPageRuleResult(self, prr):

#    debug("[DataRuleResult][addPageRuleResult] " + str(prr.rule_id))

    if prr.elements_hidden > 0:
      self.rules_with_hidden_content += 1

    self.addResult(prr)

  def addResult(self, r):
    self.addRuleResult(r)
    self.rule_results.append(r)
    self.calculateImplementation()

  def addRuleResult(self, rr):

#    debug("[DataRuleResult][addRuleResult]: " + str(rr.result_value))

    if rr.result_value == RULE_RESULT.NOT_APPLICABLE:
      self.rules_na += 1
    elif rr.result_value == RULE_RESULT.PASS:
      self.rules_passed += 1
    elif rr.result_value == RULE_RESULT.MANUAL_CHECK:
      self.rules_manual_check += 1
    elif rr.result_value == RULE_RESULT.WARNING:
      self.rules_warning += 1
    elif rr.result_value == RULE_RESULT.VIOLATION:
      self.rules_violation += 1

  def updateRuleResults(self):

#    debug("[DataRuleResult][updateRuleResults]: " + str(len(self.rule_results)) + " results")

    self.rules_na           = 0
    self.rules_passed       = 0
    self.rules_manual_check = 0
    self.rules_warning      = 0
    self.rules_violation    = 0

    self.rules_with_hidden_content    = 0

    self.result_value = RULE_RESULT.NOT_APPLICABLE

    self.implementation_pass_fail_score  = -1
    self.implementation_pass_fail_status = "U"

    self.implementation_score      = -1
    self.implementation_score_fail = -1
    self.implementation_score_mc   = -1
    self.implementation_status     = "U"

    for rr in self.rule_results:
      self.addRuleResult(rr)

    self.calculateImplementation()

  def calculateImplementation(self):

    def set_status(score, label):
      if pass_fail_count and score <= self.implementation_pass_fail_score:
        self.implementation_pass_fail_status = label

      if count and score <= self.implementation_score:
        if pass_fail_total == 0:
          self.implementation_status = "MC"
        elif count == pass_fail_count:
          self.implementation_status = label
        else:
          self.implementation_status = label + "-MC"

    pass_fail_total = 0
    pass_fail_count = 0
    pass_fail_count_complete = 0

    total      = 0
    total_fail = 0
    count      = 0
    count_complete = 0

    for r in self.rule_results:
      if r.implementation_pass_fail_score >= 0:
        pass_fail_total += r.implementation_pass_fail_score
        pass_fail_count += 1
        if r.implementation_pass_fail_status == 'C':
          pass_fail_count_complete += 1

      if r.implementation_score >= 0:
        total      += r.implementation_score
        total_fail += r.implementation_score_fail
        count      += 1
        if r.implementation_status == 'C':
          count_complete += 1

      if r.result_value > self.result_value:
        self.result_value = r.result_value

#    debug("[DataRuleResult][calculateImplementation] 2")
    if pass_fail_count > 0:
      self.implementation_pass_fail_score = int(round(pass_fail_total / pass_fail_count))

#    debug("[DataRuleResult][calculateImplementation] 3")
    if count > 0:
      self.implementation_score      = total / count
      self.implementation_score_fail = total_fail / count
      self.implementation_score_mc   = 100 - self.implementation_score - self.implementation_score_fail

    set_status(  0, 'NI')
    set_status( 50, 'PI')
    set_status( 95, 'AC')

    if (pass_fail_count == pass_fail_count_complete) and (pass_fail_count_complete > 0):
      self.implementation_pass_fail_status = 'C'
    elif self.implementation_pass_fail_score > 99:
      self.implementation_pass_fail_score = 99

    if (count == count_complete) and (count_complete > 0):
      self.implementation_status = "C"
    elif self.implementation_score > 99:
      self.implementation_score = 99


#    debug("[DataRuleResult][calculateImplementation] 4")


# ---------------------------------------------------------------
#
# DataPageRuleResult
#
# ---------------------------------------------------------------

class DataPageRuleResult(DataResult):

  def __init__(self, rr):
    super(DataPageRuleResult, self).__init__()

#    debug("[DataPageRuleResult][__init__] " + rr["rule_id"])

    self.rule_id               = rr["rule_id"]
    self.slug                  = rule_refs.getRule(rr["rule_id"]).slug

#    debug("[DataPageRuleResult][__init__] A")

    self.rule_required         = rr["rule_required"]

    self.rule_category_code    = rr["rule_category_code"]
    self.rule_scope_code       = rr["rule_scope_code"]
    self.guideline_number      = rr["guideline_code"]

    self.result_value            = rr["result_value"]
    self.result_message          = rr["result_message"]

    self.elements_violation      = rr["elements_violation"]
    self.elements_warning        = rr["elements_warning"]
    self.elements_mc_identified  = rr["elements_manual_check"]
    self.elements_mc_passed      = 0
    self.elements_mc_failed      = 0
    self.elements_mc_na          = 0
    self.elements_hidden         = rr["elements_hidden"]
    self.elements_passed         = rr["elements_passed"]


#    debug("[DataPageRuleResult][__init__] B")

    self.element_results_json  = ""

    try:
      self.element_results_json  = json.dumps(rr["element_results"])
    except:
      pass

#    debug("[DataPageRuleResult][__init__] C")

  def __str__(self):
    return "Page Rule Result: " + self.result_value_nls + " (" + self.rule_id + ")"

  def calculate_implementation(self):

    def set_status(score, label):
      if pass_fail_total and score <= self.implementation_pass_fail_score:
        self.implementation_pass_fail_status = label

      if total and score <= self.implementation_score:
        if pass_fail_total == 0:
          self.implementation_status = "MC"
        elif total == pass_fail_total:
          self.implementation_status = label
        else:
          self.implementation_status = label + "-MC"

    self.implementation_pass_fail_score  = -1
    self.implementation_score            = -1
    self.implementation_score_fail       = -1
    self.implementation_score_mc         = -1

    self.implementation_pass_fail_status = "NA"
    self.implementation_status           = "NA"

    passed = self.elements_passed + self.elements_mc_passed
    failed = self.elements_violation + self.elements_warning + self.elements_mc_failed

    pass_fail_total = passed + failed

    total = self.elements_mc_identified - self.elements_mc_passed - self.elements_mc_failed - self.elements_mc_na

    if total > 0:
      total = pass_fail_total + total
    else:
      total = pass_fail_total


    if pass_fail_total:
      self.implementation_pass_fail_score =  (100 * passed) / pass_fail_total

    if total > 0:
      self.implementation_score      = (100 * passed) / total
      self.implementation_score_fail = (100 * failed) / total
      self.implementation_score_mc   = 100 - self.implementation_score - self.implementation_score_fail

    set_status( 0, 'NI')
    set_status( 50, 'PI')
    set_status( 95, 'AC')

    if (pass_fail_total == passed) and (pass_fail_total > 0):
      self.implementation_pass_fail_status = 'C'

    if (total == passed) and (total > 0):
      self.implementation_status = "C"


#    debug("[DataPageRuleResult][calaculate_implementation]           score: " + str(self.implementation_score))


  def saveToDjango(self, data_page_result, page_result, website_rule_result):

    r = rule_refs.getRule(self.rule_id)
#    debug("[DataPageRuleResult][saveToDjango] " + str(r.rule_id))

    prcr = data_page_result.getPageRuleCategoryResult(self.rule_category_code)
#    debug("[DataPageRuleResult][saveToDjango] " + str(prcr.sql_id))

    pglr  = data_page_result.getPageGuidelineResult(self.guideline_number)
#    debug("[DataPageRuleResult][saveToDjango] " + str(pglr.sql_id))

    prsr = data_page_result.getPageRuleScopeResult(self.rule_scope_code)
#    debug("[DataPageRuleResult][saveToDjango] " + str(prsr.sql_id))

#    debug("[DataPageRuleResult][saveToDjango] A")

    self.addColumnValue("rule_id", r.id)
    self.addColumnValue("slug", self.slug)
    self.addColumnValue("rule_required", self.rule_required)
    self.addColumnValue("ws_rule_result_id", website_rule_result.sql_id)
    self.addColumnValue("page_result_id", page_result.id)
    self.addColumnValue("page_rc_result_id", prcr.sql_id)
    self.addColumnValue("page_gl_result_id", pglr.sql_id)
    self.addColumnValue("page_rs_result_id", prsr.sql_id)
    self.addColumnValue("elements_passed", self.elements_passed)
    self.addColumnValue("elements_violation", self.elements_violation)
    self.addColumnValue("elements_warning", self.elements_warning)
    self.addColumnValue("elements_mc_identified", self.elements_mc_identified)
    self.addColumnValue("elements_mc_failed", 0)
    self.addColumnValue("elements_mc_passed", 0)
    self.addColumnValue("elements_mc_na", 0)
    self.addColumnValue("elements_hidden", self.elements_hidden)
    self.addColumnValue("element_results_json", escapeSingleQuotes(str(self.element_results_json)))
    self.addColumnValue("result_message" , escapeSingleQuotes(self.result_message))

#    debug("[DataPageRuleResult][saveToDjango] B")

    try:
      super(DataPageRuleResult, self).saveToDjango('pageResults_pageruleresult')
    except:
      error("[DataPageRuleResult][saveToDjango] SQL insert error")

    # for testing only
    try:
      page_rule_result = PageRuleResult.objects.get(page_result=page_result, rule=r)
    except:
      error("[DataPageRuleResult][saveToDjango] SQL select error " + str(r))

#    debug("  found Page Evaluation Rule Result: " + str(page_eval_rule_result.id))

# ---------------------------------------------------------------
#
# DataPageRuleCategoryResult
#
# ---------------------------------------------------------------

class DataPageRuleCategoryResult(DataRuleResult):

  def __init__(self, code):

    self.rule_category_code = code
    self.slug = rule_category_refs.getRuleCategory(code).slug

    super(DataPageRuleCategoryResult, self).__init__()


  def __str__(self):
    s = "Page RC: "
    s += super(DataPageRuleCategoryResult, self).__str__()
    return s

  def saveToDjango(self, page_result, sql_id):

    rc = rule_category_refs.getRuleCategory(self.rule_category_code)

#    debug("[DataPageRuleCategoryResult][saveToDjango][rc]: " + str(rc))
#    debug("[DataPageRuleCategoryResult][saveToDjango][sql_id]: " + str(sql_id))

    self.addColumnValue("rule_category_id", rc.id)
    self.addColumnValue("page_result_id", page_result.id)
    self.addColumnValue("ws_rc_result_id", sql_id)
    self.addColumnValue("slug", self.slug)

    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("total_pages_pass_fail", "0")
    self.addColumnValue("has_manual_checks", "false")


    try:
      super(DataPageRuleCategoryResult, self).saveToDjango('pageResults_pagerulecategoryresult')
    except:
      error("[DataPageRuleCategoryResult][saveToDjango] SQL insert error")

    try:
      page_rc_result = PageRuleCategoryResult.objects.get(page_result=page_result, rule_category=rc)
      self.sql_id = str(page_rc_result.id)
    except:
      error("[DataPageRuleCategoryResult][saveToDjango] SQL select error " + str(rc))


# ---------------------------------------------------------------
#
# DataPageRuleScopeResult
#
# ---------------------------------------------------------------

class DataPageRuleScopeResult(DataRuleResult):

  def __init__(self, rsc):

#    debug("[DataPageRuleScopeResult][__init__] " + str(rsc))

    self.rule_scope_code = rsc
    self.slug = rule_scope_refs.getRuleScope(rsc).slug

    super(DataPageRuleScopeResult, self).__init__()

  def __str__(self):
    s = "Page RS: "
    s += super(DataPageRuleScopeResult, self).__str__()
    return s

  def saveToDjango(self, page_result, sql_id):

    rs = rule_scope_refs.getRuleScope(self.rule_scope_code)

#    debug("DataPageRuleScopeResult][saveToDjango] " + str(rs))

    self.addColumnValue("rule_scope_id", rs.id)
    self.addColumnValue("page_result_id", page_result.id)
    self.addColumnValue("ws_rs_result_id", sql_id)
    self.addColumnValue("slug", self.slug)

    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("total_pages_pass_fail", "0")
    self.addColumnValue("has_manual_checks", "false")

    try:
      super(DataPageRuleScopeResult, self).saveToDjango('pageResults_pagerulescoperesult')
    except:
      error("[DataPageRuleScopeResult][saveToDjango] SQL insert error")

    try:
      page_rs_result = PageRuleScopeResult.objects.get(page_result=page_result, rule_scope=rs)
      self.sql_id = str(page_rs_result.id)
    except:
      error("[DataPageRuleScopeResult][saveToDjango] SQL select error " + str(rs))

#    debug("  found Page Evaluation Rule Scope Result: " + str(page_eval_rs_result.id))

# ---------------------------------------------------------------
#
# DataPageGuidelineResult
#
# ---------------------------------------------------------------

class DataPageGuidelineResult(DataRuleResult):

  def __init__(self, num):
    self.guideline_number = num

#    debug("[DataPageGuidelineResult][__init__] " + str(num))

    self.slug = guideline_refs.getGuideline(num).slug

    super(DataPageGuidelineResult, self).__init__()

  def __str__(self):
    s = "Page GL: "
    s += super(DataPageGuidelineResult, self).__str__()
    return s

  def saveToDjango(self, page_result, sql_id):

    gl = guideline_refs.getGuideline(self.guideline_number)

#    debug("[DataPageGuidelineResult][saveToDjango] " + str(gl))

    self.addColumnValue("guideline_id", gl.id)
    self.addColumnValue("page_result_id", page_result.id)
    self.addColumnValue("ws_gl_result_id", sql_id)
    self.addColumnValue("slug", self.slug)

    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("total_pages_pass_fail", "0")
    self.addColumnValue("has_manual_checks", "false")

    try:
      super(DataPageGuidelineResult, self).saveToDjango('pageResults_pageguidelineresult')
    except:
      error("[DataPageGuidelineResult][saveToDjango] SQL insert error")

    try:
      page_gl_result = PageGuidelineResult.objects.get(page_result=page_result, guideline=gl)
      self.sql_id = str(page_gl_result.id)
    except:
      error("[DataPageGuidelineResult][saveToDjango] SQL select error " + str(gl))

 #   debug("  found Page Evaluation Guideline Result: " + str(page_eval_g_result.id))

# ---------------------------------------------------------------
#
# DataPageResult
#
# ---------------------------------------------------------------

class DataPageResult(DataRuleResult):

  def __init__(self, wsr, num, url, url_encoded, title, mi):

    self.wsr = wsr

    self.page_number = num + 1

    if len(url) > 4094:
      self.url  = url[4090:]
    else:
      self.url  = url

    if len(url_encoded) > 8190:
      self.url_encoded  = url[4090:]
    else:
      self.url_encoded  = url_encoded

    if len(title) > 510:
      self.title = url[510:]
    else:
      self.title = title

    self.page_rule_category_results = []
    self.page_guideline_results     = []
    self.page_rule_scope_results    = []

    self.page_rule_results         = []

    if mi:
      self.markup_info = PageMarkupInformation(mi, log)
    else:
      self.markup_info = False

    super(DataPageResult, self).__init__()

  def __str__(self):
    s = "Page Result: "
    s += super(DataPageResult, self).__str__()
    return s

  def addPageRuleResult(self, prr):

#    debug("[DataPageResult][addPageRuleResult] 1")

    super(DataPageResult, self).addPageRuleResult(prr)

#    debug("[DataPageResult][addPageRuleResult] 2")

    self.page_rule_results.append(prr)

#    debug("[DataPageResult][addPageRuleResult] 3")

    prcr = self.getPageRuleCategoryResult(prr.rule_category_code)
    if prcr:
      prcr.addPageRuleResult(prr)

#    debug("[DataPageResult][addPageRuleResult] 4")

    pgr =  self.getPageGuidelineResult(prr.guideline_number)
    if pgr:
      pgr.addPageRuleResult(prr)

#    debug("[DataPageResult][addPageRuleResult] 5")

    prsr =  self.getPageRuleScopeResult(prr.rule_scope_code)
    if prsr:
      prsr.addPageRuleResult(prr)

#    debug("[DataPageResult][addPageRuleResult] 6")

  def getPageRuleCategoryResult(self, code):

    for prcr in self.page_rule_category_results:
      if prcr.rule_category_code == code:
        return prcr

    prcr = DataPageRuleCategoryResult(code)
    self.page_rule_category_results.append(prcr)
    return prcr


  def getPageGuidelineResult(self, num):

    for pgr in self.page_guideline_results:
      if pgr.guideline_number == num:
        return pgr

    pgr = DataPageGuidelineResult(num)
    self.page_guideline_results.append(pgr)
    return pgr


  def getPageRuleScopeResult(self, code):

    for prsr in self.page_rule_scope_results:
      if prsr.rule_scope_code == code:
        return prsr

    prsr = DataPageRuleScopeResult(code)
    self.page_rule_scope_results.append(prsr)
    return prsr


  def saveToDjango(self, data_website_result, ws_report):

#    debug("========================================================")
#    debug("[DataPageResult][saveToDango]" + self.url)

    self.addColumnValue("ws_report_id", ws_report.id)
    self.addColumnValue("page_number", self.page_number)
    self.addColumnValue("url", escapeSingleQuotes(self.url))
    self.addColumnValue("url_encoded", escapeSingleQuotes(self.url_encoded))
    self.addColumnValue("title", escapeSingleQuotes(self.title))

    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("total_pages_pass_fail", "0")
    self.addColumnValue("has_manual_checks", "false")

#    debug("[DataPageResult][saveToDango] A ")

    try:
      super(DataPageResult, self).saveToDjango('pageResults_pageresult')
    except:
      error("[DataPageResult][saveToDango] SQL insert error")

    try:
      page_result = PageResult.objects.get(ws_report=ws_report, page_number=self.page_number)
    except:
      error("[DataPageResult][saveToDango] SQL select error " + str(self.page_number))

#    debug("[DataPageResult][saveToDango] Saving Page Rule Category Results...")
    for prcr in self.page_rule_category_results:
      wsrcr = data_website_result.getWebsiteRuleCategoryResult(prcr.rule_category_code)
      prcr.saveToDjango(page_result, wsrcr.sql_id)

#    debug("[DataPageResult][saveToDango] Saving Page Guideline Results...")
    for pgr in self.page_guideline_results:
      wsgr = data_website_result.getWebsiteGuidelineResult(pgr.guideline_number)
      pgr.saveToDjango(page_result, wsgr.sql_id)

#    debug("[DataPageResult][saveToDango] Saving Page Rule Scope Results...")
    for prsr in self.page_rule_scope_results:
      wsrsr = data_website_result.getWebsiteRuleScopeResult(prsr.rule_scope_code)
      prsr.saveToDjango(page_result, wsrsr.sql_id)

#    debug("[DataPageResult][saveToDango] Saving " + str(len(self.rule_results)) + " Page Rule Results..." )
    for prr in self.rule_results:
      debug("[DataPageResult][saveToDjango][prr.rule_id][A]: " + str(prr.rule_id))
      wsrr = data_website_result.getWebsiteRuleResult(prr.rule_id, False)
      debug("[DataPageResult][saveToDjango][wsrr.rule_id][B]: " + str(wsrr.rule_id))
      prr.saveToDjango(self, page_result, wsrr)

#    debug("[DataPageResult][saveToDango] Saving Page Markup Information...")
    if self.markup_info:
      self.markup_info.saveToDjango(page_result)



# ---------------------------------------------------------------
#
# WebsiteRuleResult
#
# ---------------------------------------------------------------

class DataWebsiteRuleResult(DataResult):

  def __init__(self, prr):

    super(DataWebsiteRuleResult, self).__init__()

    self.rule_id = prr.rule_id
    self.slug    = rule_refs.getRule(prr.rule_id).slug

    self.rule_required = prr.rule_required

    self.rule_category_code = prr.rule_category_code
    self.guideline_number   = prr.guideline_number
    self.rule_scope_code    = prr.rule_scope_code

    self.sql_id = False

    self.page_count         = 0

    self.pages_na           = 0
    self.pages_passed       = 0
    self.pages_manual_check = 0
    self.pages_warning      = 0
    self.pages_violation    = 0

    self.pages_with_hidden_content = 0

    self.elements_violation      = 0
    self.elements_warning        = 0
    self.elements_mc_identified  = 0
    self.elements_mc_passed      = 0
    self.elements_mc_failed      = 0
    self.elements_mc_na          = 0
    self.elements_hidden         = 0
    self.elements_passed         = 0

    self.page_rule_results = []

  def __str__(self):
    return "[DataWebsiteRuleResult] " + self.rule_id + " V: %6d W: %6d MC: %6d P: %6d MC: %6d" % (self.rules_violation, self.rules_warning, self.rules_manual_check, self.rules_passed, self.rules_na)

  def addPageRuleResult(self, prr):

#    debug("[WebsiteRuleResult][addPageRuleResult]: 1 ")

    self.page_count  += 1

    if prr.result_value == RULE_RESULT.NOT_APPLICABLE:
      self.pages_na += 1
    elif prr.result_value == RULE_RESULT.PASS:
      self.pages_passed += 1
    elif prr.result_value == RULE_RESULT.MANUAL_CHECK:
      self.pages_manual_check += 1
    elif prr.result_value == RULE_RESULT.WARNING:
      self.pages_warning += 1
    elif prr.result_value == RULE_RESULT.VIOLATION:
      self.pages_violation += 1
    else:
      self.pages_na += 1

    if prr.elements_hidden > 0:
      self.pages_with_hidden_content += 1


    self.elements_violation      += prr.elements_violation
    self.elements_warning        += prr.elements_warning
    self.elements_mc_identified  += prr.elements_mc_identified
    self.elements_mc_passed      += prr.elements_mc_passed
    self.elements_mc_failed      += prr.elements_mc_failed
    self.elements_mc_na          += prr.elements_mc_na
    self.elements_passed         += prr.elements_passed
    self.elements_hidden         += prr.elements_hidden


#    debug("[WebsiteRuleResult][addPageRuleResult]: 2 ")

    self.calculateImplementation()

  def calculateImplementation(self):

    def set_status(score, label):
      if pass_fail_total and score <= self.implementation_pass_fail_score:
        self.implementation_pass_fail_status = label

      if total and score <= self.implementation_score:
        if pass_fail_total == 0:
          self.implementation_status = "MC"
        elif total == pass_fail_total:
          self.implementation_status = label
        else:
          self.implementation_status = label + "-MC"

#    debug("[WebsiteRuleResult][calculateImplementation]: 1 ")

    if self.pages_violation > 0:
      self.result_value = RULE_RESULT.VIOLATION
    elif self.pages_warning > 0:
      self.result_value = RULE_RESULT.WARNING
    elif self.pages_manual_check > 0:
      self.result_value = RULE_RESULT.MANUAL_CHECK
    elif self.pages_passed > 0:
      self.result_value = RULE_RESULT.PASS
    else:
      self.result_value = RULE_RESULT.NOT_APPLICABLE

    self.implementation_pass_fail_score  = -1
    self.implementation_score       = -1
    self.implementation_score_fail  = -1
    self.implementation_score_mc    = -1
    self.implementation_status      = "U"

#    debug("[WebsiteRuleResult][calculateImplementation]: 2a ")

    pass_fail_total = self.elements_violation + self.elements_warning + self.elements_passed + self.elements_mc_passed + self.elements_mc_failed

    total = self.elements_mc_identified - self.elements_mc_passed - self.elements_mc_failed - self.elements_mc_na

    if total > 0:
      total = pass_fail_total + total
    else:
      total = pass_fail_total

    passed = self.elements_passed + self.elements_mc_passed
    failed = self.elements_violation + self.elements_warning + self.elements_mc_failed

#    debug("[WebsiteRuleResult][calculateImplementation]         [passed]: " + str(passed))
#    debug("[WebsiteRuleResult][calculateImplementation][pass_fail_total]: " + str(pass_fail_total))

    if pass_fail_total > 0:
      self.implementation_pass_fail_score =  (100 * passed) / pass_fail_total

#    debug("[WebsiteRuleResult][calculateImplementation][implementation_pass_fail_score]: " + str(self.implementation_pass_fail_score))

    if total > 0:
      self.implementation_score      =  (100 * passed) / total
      self.implementation_score_fail =  (100 * failed) / total
      self.implementation_score_mc   =  100 - self.implementation_score - self.implementation_score_fail

#    debug("[WebsiteRuleResult][calculateImplementation][implementation_score]: " + str(self.implementation_score))

#    debug("[WebsiteRuleResult][calculateImplementation]: 4 ")

    set_status( 0, 'NI')
    set_status( 50, 'PI')
    set_status( 95, 'AC')

#    debug("[WebsiteRuleResult][calculateImplementation]: 5 ")

    if (pass_fail_total == passed) and (pass_fail_total > 0):
      self.implementation_pass_fail_status = 'C'
    elif self.implementation_pass_fail_score > 99:
      self.implementation_pass_fail_score = 99

    if (total == passed) and (total > 0):
      self.implementation_status = "C"
    elif self.implementation_score > 99:
      self.implementation_score = 99


#

  def saveToDjango(self, data_ws_result, ws_report):
#    debug("[DataWebsiteRuleResult][saveToDjango] " + self.rule_id)

    r = rule_refs.getRule(self.rule_id)
#    debug("[DataWebsiteRuleResult][saveToDjango] 2 " + str(r.id))
    wsrcr = data_ws_result.getWebsiteRuleCategoryResult(self.rule_category_code)
#    debug("[DataWebsiteRuleResult][saveToDjango] 3 " + str(wsrcr.sql_id))
    wsglr  = data_ws_result.getWebsiteGuidelineResult(self.guideline_number)
#    debug("[DataWebsiteRuleResult][saveToDjango] 4 " + str(wsglr.sql_id))
    wsrsr = data_ws_result.getWebsiteRuleScopeResult(self.rule_scope_code)
#    debug("[DataWebsiteRuleResult][saveToDjango] 5 " + str(wsrsr.sql_id))

    self.addColumnValue("rule_id", r.id)
    self.addColumnValue("slug", self.slug)
    self.addColumnValue("ws_report_id", ws_report.id)
    self.addColumnValue("ws_rc_result_id", wsrcr.sql_id)
    self.addColumnValue("ws_gl_result_id", wsglr.sql_id)
    self.addColumnValue("ws_rs_result_id", wsrsr.sql_id)
    self.addColumnValue("rule_number", -1)
    self.addColumnValue("rule_required", self.rule_required)
    self.addColumnValue("pages_violation", self.pages_violation)
    self.addColumnValue("pages_warning", self.pages_warning)
    self.addColumnValue("pages_manual_check", self.pages_manual_check)
    self.addColumnValue("pages_passed", self.pages_passed)
    self.addColumnValue("pages_na", self.pages_na)
    self.addColumnValue("pages_with_hidden_content", self.pages_with_hidden_content)

    self.addColumnValue("elements_violation", self.elements_violation)
    self.addColumnValue("elements_warning", self.elements_warning)
    self.addColumnValue("elements_mc_identified", self.elements_mc_identified)
    self.addColumnValue("elements_mc_failed", self.elements_mc_failed)
    self.addColumnValue("elements_mc_passed", self.elements_mc_passed)
    self.addColumnValue("elements_mc_na", self.elements_mc_na)
    self.addColumnValue("elements_passed", self.elements_passed)
    self.addColumnValue("elements_hidden", self.elements_hidden)

#    debug("[DataWebsiteRuleResult][saveToDjango] 6")

    try:
      super(DataWebsiteRuleResult, self).saveToDjango("websiteResults_websiteruleresult")
    except:
      error("[DataWebsiteRuleResult][saveToDjango] SQL insert error: ")

    try:
      ws_rule_result = WebsiteRuleResult.objects.get(ws_report=ws_report, rule=r)
      self.sql_id = str(ws_rule_result.id)
    except:
      error("[DataWebsiteRuleResult][saveToDjango] SQL select error")


# ------------------------------------------------------------------------------------------------------------------------
#
# WebsiteRuleCategoryResult
#
# ------------------------------------------------------------------------------------------------------------------------

class DataWebsiteRuleCategoryResult(DataRuleResult):

  def __init__(self, code):
    self.rule_category_code = code
    self.slug = rule_category_refs.getRuleCategory(code).slug

    self.page_rc_results = []

    super(DataWebsiteRuleCategoryResult, self).__init__()

  def __str__(self):
    s = "Website RC: "
    s += super(DataWebsiteRuleCategoryResult, self).__str__()
    return s

  def addPageRuleCategoryResult(self, prcr):
    self.page_rc_results.append(prcr)

  def saveToDjango(self, ws_report):

    rc = rule_category_refs.getRuleCategory(self.rule_category_code)


    self.addColumnValue("ws_report_id", ws_report.id)
    self.addColumnValue("rule_category_id", rc.id)
    self.addColumnValue("slug", self.slug)
    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages_pass_fail", "0")

    self.addColumnValue("has_manual_checks", "false")

#    debug("[DataWebsiteRuleCategoryResult][saveToDjango][A][rc.category_id] " + str(rc.category_id))

    try:
      super(DataWebsiteRuleCategoryResult, self).saveToDjango("websiteResults_websiterulecategoryresult")
    except:
      error("[DataWebsiteRuleCategoryResult][saveToDjango] SQL insert error ")

#    debug("[DataWebsiteRuleCategoryResult][saveToDjango][B] ")

    try:
      ws_rc_result = WebsiteRuleCategoryResult.objects.get(ws_report=ws_report, rule_category=rc)
      self.sql_id = str(ws_rc_result.id)
    except:
      error("[DataWebsiteRuleCategoryResult][saveToDjango] SQL select error")

    debug("[DataWebsiteRuleCategoryResult][saveToDjango][C][sql_id] " + str(self.sql_id))


# -----------------------------------------------------------------------------
#
# WebsiteGuidelineResult
#
# -----------------------------------------------------------------------------

class DataWebsiteGuidelineResult(DataRuleResult):

  def __init__(self, num):
    self.guideline_number = num
    self.slug = guideline_refs.getGuideline(num).slug

    self.page_gl_results = []


    super(DataWebsiteGuidelineResult, self).__init__()

  def __str__(self):
    s = "Website GL " + self.guideline_number + ": "
    s += super(DataWebsiteGuidelineResult, self).__str__()
    return s

  def addPageGuidelineResult(self, pglr):
    self.page_gl_results.append(pglr)

  def saveToDjango(self, ws_report):

    gl = guideline_refs.getGuideline(self.guideline_number)

    self.addColumnValue("ws_report_id", ws_report.id)
    self.addColumnValue("guideline_id", gl.id)
    self.addColumnValue("slug", self.slug)
    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("total_pages_pass_fail", "0")
    self.addColumnValue("has_manual_checks", "false")

    try:
      super(DataWebsiteGuidelineResult, self).saveToDjango("websiteResults_websiteguidelineresult")
    except:
      error("[DataWebsiteGuidelineResult][saveToDjango] SQL insert error")

    try:
      ws_eval_gl_result = WebsiteGuidelineResult.objects.get(ws_report=ws_report, guideline=gl)
      self.sql_id = str(ws_eval_gl_result.id)
    except:
      error("[DataWebsiteGuidelineResult][saveToDjango] SQL select error: " + str(guideline))

#    debug("[DataWebsiteGuidelineResult][saveToDjango] Found Website Evaluation Guideline Result: " + str(ws_eval_g_result.id))

# ---------------------------------------------------------------
#
# WebsiteRuleScopeResult
#
# ---------------------------------------------------------------

class DataWebsiteRuleScopeResult(DataRuleResult):

  def __init__(self, code):
    self.rule_scope_code = code
    self.slug = rule_scope_refs.getRuleScope(code).slug

    self.page_rs_results = []


    super(DataWebsiteRuleScopeResult, self).__init__()

  def __str__(self):
    s = "Website RS: "
    s += super(DataWebsiteRuleScopeResult, self).__str__()
    return s

  def addPageRuleScopeResult(self, prsr):
    self.page_rs_results.append(prsr)

  def saveToDjango(self, ws_report):

    rs = rule_scope_refs.getRuleScope(self.rule_scope_code)

    self.addColumnValue("ws_report_id", ws_report.id)
    self.addColumnValue("rule_scope_id", rs.id)
    self.addColumnValue("slug", rs.slug)
    self.addColumnValue("implementation_pass_fail_summ", "0")
    self.addColumnValue("implementation_summ", "0")
    self.addColumnValue("implementation_summ_fail", "0")
    self.addColumnValue("total_pages", "0")
    self.addColumnValue("total_pages_pass_fail", "0")
    self.addColumnValue("has_manual_checks", "false")

    try:
      super(DataWebsiteRuleScopeResult, self).saveToDjango("websiteResults_websiterulescoperesult")
    except:
      error("[DataWebsiteRuleScopeResult][saveToDjango] SQL insert error")

    try:
      ws_eval_rs_result = WebsiteRuleScopeResult.objects.get(ws_report=ws_report, rule_scope=rs)
      self.sql_id = str(ws_eval_rs_result.id)
    except:
      error("[DataWebsiteRuleScopeResult][saveToDjango] SQL select error: " + str(rs))

#    debug("  Found Website Evaluation Rule Scope Result: " + str(ws_eval_rs_result.id))

# ---------------------------------------------------------------
#
# WebsiteResult
#
# ---------------------------------------------------------------

class DataWebsiteResult(DataRuleResult):

  def __init__(self, wsr):
    self.ws_report = wsr

    self.page_count         = 0
    self.page_results = []

    self.website_rule_category_results = []
    self.website_guideline_results     = []
    self.website_rule_scope_results    = []

    super(DataWebsiteResult, self).__init__()

  def __str__(self):
    s = "Website Result: "
    s += super(DataWebsiteResult, self).__str__()
    return s

  def addPageResult(self, pr):

#    debug("[DataWebsiteResult][addPageResult] " + pr.url_encoded)

    # If url is already in, do not include again
    # his can happen for page redirects and 404 and other error pages
    if self.urlUnique(pr):

      self.page_count  += 1
      self.page_results.append(pr)

#      debug("[DataWebsiteResult][addPageResult]: 1 ")

      for prr in pr.rule_results:
#        debug("[DataWebsiteResult][addPageResult][prr]: "  + prr.rule_id)
        wsrr = self.getWebsiteRuleResult(prr.rule_id, prr)
#        debug("[DataWebsiteResult][addPageResult][wsrr]: "  + wsrr.rule_id)
        wsrr.addPageRuleResult(prr)

#      debug("[DataWebsiteResult][addPageResult]: 2 " + str(len(pr.page_rule_category_results)))

      for prcr in pr.page_rule_category_results:
        wsrcr = self.getWebsiteRuleCategoryResult(prcr.rule_category_code)
        wsrcr.addPageRuleCategoryResult(prcr)
        wsrcr.updateRuleResults()

#      debug("[DataWebsiteResult][addPageResult]: 3 " + str(len(pr.page_guideline_results)))

      for pglr in pr.page_guideline_results:
        wsglr = self.getWebsiteGuidelineResult(pglr.guideline_number)
        wsglr.addPageGuidelineResult(pglr)
        wsglr.updateRuleResults()

#      debug("[DataWebsiteResult][addPageResult]: 4 " + str(len(pr.page_rule_scope_results)))

      for prsr in pr.page_rule_scope_results:
        wsrsr = self.getWebsiteRuleScopeResult(prsr.rule_scope_code)
        wsrsr.addPageRuleScopeResult(prsr)
        wsrsr.updateRuleResults()

      self.updateRuleResults()

    else:
      debug("[DataWebsiteResult][saveToDjango] URL already included in page results: " + pr.url)

#    debug("[WebsiteResult][addPageResult]: done ")

    return

  def urlUnique(self, pr_test):

    for pr in self.page_results:
      if pr.url == pr_test.url:
        return False

    return True

  def getWebsiteRuleResult(self, rule_id, page_rule_result):

#    debug("[DataWebsiteResult][getWebsiteRuleResult][page_rule_result]: " + str(rule_id))

    for wsrr in self.rule_results:
      if wsrr.rule_id == rule_id:
        return wsrr

    if not page_rule_result:
      return False

    wsrr = DataWebsiteRuleResult(page_rule_result)
    self.rule_results.append(wsrr)

    try:
      wsrcr = self.getWebsiteRuleCategoryResult(page_rule_result.rule_category_code)
      wsrcr.rule_results.append(wsrr)
    except:
      error("[DataWebsiteResult][getWebsiteRuleResult]: getting website rule category result " + str(page_rule_result.rule_category_code))

    try:
      wsgr = self.getWebsiteGuidelineResult(page_rule_result.guideline_number)
      wsgr.rule_results.append(wsrr)
    except:
      error("[DataWebsiteResult][getWebsiteRuleResult]: getting website guideline result " + str(page_rule_result.guideline_number))

    try:
      wsrsr = self.getWebsiteRuleScopeResult(page_rule_result.rule_scope_code)
      wsrsr.rule_results.append(wsrr)
    except:
      error("[DataWebsiteResult][getWebsiteRuleResult]: website rule scope result " + str(page_rule_result.rule_scope_code))

    return wsrr

  def getWebsiteRuleCategoryResult(self, code):

#    debug("[WebsiteResult][getWebsiteRuleCategoryResult]: 1 ")

    for wsrcr in self.website_rule_category_results:
      if wsrcr.rule_category_code == code:
        return wsrcr

#    debug("[WebsiteResult][getWebsiteRuleCategoryResult]: 2 ")

    wsrcr = DataWebsiteRuleCategoryResult(code)
    self.website_rule_category_results.append(wsrcr)
    return wsrcr

  def getWebsiteGuidelineResult(self, num):

#    debug("[WebsiteResult][getWebsiteGuidelineResult]: 1 ")

    for wsgr in self.website_guideline_results:
      if wsgr.guideline_number == num:
        return wsgr

#    debug("[WebsiteResult][getWebsiteGuidelineResult]: 2 ")

    wsgr = DataWebsiteGuidelineResult(num)
    self.website_guideline_results.append(wsgr)
    return wsgr

  def getWebsiteRuleScopeResult(self, code):

#    debug("[WebsiteResult][getWebsiteRuleScopeResult]: 1 ")

    for wsrsr in self.website_rule_scope_results:
      if wsrsr.rule_scope_code == code:
        return wsrsr

#    debug("[WebsiteResult][getWebsiteRuleScopeResult]: 2 ")

    wsrsr = DataWebsiteRuleScopeResult(code)
    self.website_rule_scope_results.append(wsrsr)
    return wsrsr


  def saveToDjango(self):

    if (self.ws_report):
      try:

        start = time.time()
        info("Report Title:  " + str(self.ws_report.title))

        wsr = self.ws_report

        try:
          wsr.rules_violation     = self.rules_violation
          wsr.rules_warning       = self.rules_warning
          wsr.rules_manual_check  = self.rules_manual_check
          wsr.rules_passed        = self.rules_passed
          wsr.rules_na            = self.rules_na

          wsr.result_value        = self.result_value

          wsr.implementation_pass_fail_score   = self.implementation_pass_fail_score
          wsr.implementation_pass_fail_status  = self.implementation_pass_fail_status

          wsr.implementation_score             = self.implementation_score
          wsr.implementation_score_fail        = self.implementation_score_fail
          wsr.implementation_score_mc          = self.implementation_score_mc
          wsr.implementation_status            = self.implementation_status

#          debug("[WebsiteResult][saveToDjango]: page_count= " + str(len(self.page_results)))
          wsr.page_count          = len(self.page_results)

          wsr.save()

        except:
          error("[WebsiteResult][saveToDjango]: website result")
          exit()

        info("Saving Rule Category Results")

        for wsrcr in self.website_rule_category_results:
          try:
            wsrcr.saveToDjango(self.ws_report)
          except:
            error("[WebsiteResult][saveToDjango]: website rc result")

        info("Saving Guideline Results")

        for wsgr in self.website_guideline_results:
          try:
            wsgr.saveToDjango(self.ws_report)
          except:
            error("[WebsiteResult][saveToDjango]: website gl result")

        info("Saving Rule Scope Results")

        for wsrsr in self.website_rule_scope_results:
          try:
            wsrsr.saveToDjango(self.ws_report)
          except:
            error("[WebsiteResult][saveToDjango]: website rs result")

        info("Saving Rule Results")

        for wsrr in self.rule_results:
          try:
            wsrr.saveToDjango(self, wsr)
          except:
            error("[WebsiteResult][saveToDjango]: website rule result ")

        info("Saving " + str(len(self.page_results)) + " Page Results")

        for pr in self.page_results:
          try:
            pr.saveToDjango(self, self.ws_report)
          except:
            error("[WebsiteResult][saveToDjango]: page result")

        info("Done Saving Results")

      except:
        self.ws_report.set_status_error()

      ave_time = "no pages analyzed"
      page_count = len(self.page_results)
      if page_count > 0:
        ave_time = "{:10.4f}".format((time.time()-start)/page_count) + " seconds"

#      debug('Average time to save a page to the database: ' + ave_time)

    else:
      error("Error Website Evaluation Result summary is not defined")

# ---------------------------------------------------------------
#
# saveResultsToDjango
#
# ---------------------------------------------------------------

def saveResultsToDjango(ws_report, l):

  global log
  log = l
  first = True

  def getPageDataFromJSON(num, data):

    pr = DataPageResult(wsr, num, data['eval_url'], data['eval_url_encoded'], data['eval_title'], data['markup_information'])
    debug("URL: " + pr.url_encoded)

    for rr in data["rule_results"]:
#      debug("[saveResultsToDjango][getPageDataFromJSON] --------------------------------------")

      try:
        prr = DataPageRuleResult(rr)
#        debug("[saveResultsToDjango][getPageDataFromJSON] " + rr["rule_id"] + " (" + str(prr.implementation_pass_fail_score) + ")")
        prr.calculate_implementation()
#        debug("[saveResultsToDjango][getPageDataFromJSON] " + rr["rule_id"] + " (" + str(prr.implementation_pass_fail_score) + ")")
      except:
        error("Error creating data page rule result: " + rr["rule_id"])

      try:
#        debug("[saveResultsToDjango][getPageDataFromJSON] " + rr["rule_id"] + " A(" + str(pr.implementation_pass_fail_score) + ")")
        pr.addPageRuleResult(prr)
#        debug("[saveResultsToDjango][getPageDataFromJSON] " + rr["rule_id"] + " B(" + str(pr.implementation_pass_fail_score) + ")")
      except:
        error("[saveResultsToDjango][getPageDataFromJSON] Error adding page rule result: " + rr["rule_id"])

#    debug("[saveResultsToDjango][getPageDataFromJSON] C")
    wsr.addPageResult(pr)
#    debug("[saveResultsToDjango][getPageDataFromJSON] D")

    return



  def process_file(dir_name, file_name):
    parts = file_name.split('.');
    if len(parts) == 2 and parts[1] == 'json':
      debug("Processing File: " + file_name)
      file_json = open(dir_name + "/" + file_name, 'r')
      try:
        page_data = json.load(file_json)
        g = True
      except:
        error("[saveResultsToDjango][process_file] A " + dir_name + "/" + file_name + " is not a valid JSON formatted file")
        g = False

      if g:
        try:
          num = int(parts[0][-4:])
          try:
            getPageDataFromJSON(num, page_data)
          except:
            error("[saveResultsToDjango][process_file] B " + dir_name + "/" + file_name + " getting data from JSON file (" + str(num) + ")")
        except:
          error("[saveResultsToDjango][process_file] C " + dir_name + "/" + file_name + " could not generate valid sequence number: " + parts[0])

      file_json.close()


    if file_name == "processed_urls.csv":
#      debug("[saveResultsToDjango][process_file] Retreiving processed urls information")
      processedUrlsToDatabase(ws_report, dir_name + "/" + file_name, 10)

    if file_name == "unprocessed_urls.csv":
#      debug("[saveResultsToDjango][process_file] Retreiving unprocessed urls information")
      unprocessedUrlsToDatabase(ws_report, dir_name + "/" + file_name, 7)

    if file_name == "filtered_urls.csv":
#      debug("[saveResultsToDjango][process_file] Retreiving filtered urls")
      filteredUrlsToDatabase(ws_report, dir_name + "/" + file_name, 2)

    if file_name == "status.txt":
#      debug("[saveResultsToDjango][process_file] Retreiving status information")
      file_status = open(dir_name + "/" + file_name, 'r')
# Need to update usage information
#      statusToDatabase(ws_report, file_status)

# ---------------------------------------------------------------
#
# starting point for saving information to database
#
# ---------------------------------------------------------------

  start = time.time()

  wsr = DataWebsiteResult(ws_report)

#  os.path.walk(ws_report.data_directory + "/data", lister, None)

  dir = ws_report.data_directory + "/data"
#  debug("[saveResultsToDjango][main] DATA_DIR: " + dir)

  info("===============================================================")
  info("Processing data files in " + dir)
  for root, dirs, files in os.walk(dir):
    for file_name in files:
#      debug('[saveResultsToDjango][main] ' + dir + '/' + file_name)
      process_file(dir,file_name)

  try:
    wsr.saveToDjango()
    info("Set status complete")
    ws_report.set_page_numbers()
    # save data for now
    ws_report.set_status_complete(True)

    page_count = wsr.page_count
    total = "{:10.4f}".format(time.time()-start)

    if page_count > 0:
      if page_count == 1:
        ave_time = "{:10.4f}".format(time.time()-start) + " seconds/page (1 page)"
      else:
        ave_time = "{:10.4f}".format((time.time()-start)/page_count) + " seconds/page (" + str(page_count) + " pages)"

    info("          Pages saved: " + str(page_count))
    info("           Total Time: " + total)
    info('Average time per page: ' + ave_time)

  except:
    ws_report.set_status_error()
    error("Error: saving to django")

