"""
Copyright 2014-2016 University of Illinois

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

file: websiteResults/models.py

Author: Jon Gunderson

"""

from __future__ import absolute_import

from django.db import models

from ruleCategories.models import RuleCategory
from wcag20.models         import Guideline
from rules.models          import RuleScope
from rules.models          import Rule


# Create your models here.

RESULT_VALUE = {
  'UNDEFINED'      : 0,
  'NOT_APPLICABLE' : 1,
  'PASS'           : 2,
  'MANUAL_CHECK'   : 3,
  'WARNING'        : 4,
  'VIOLATION'      : 5
}

IMPLEMENTATION_STATUS_CHOICES = (
    ('U',   'Undefined'),
    ('NA',  'Not applicable'),
    ('NI',  'Not Implemented'),
    ('PI',  'Partial Implementation'),
    ('AC',  'Almost Complete'),
    ('NI-MC',  'Not Implemented with manual checks required'),
    ('PI-MC',  'Partial Implementation with manual checks required'),
    ('AC-MC',  'Almost Complete with manual checks required'),
    ('C',   'Complete'),
)


MC_STATUS_CHOICES = (
    ('NC',  'Not Checked'),
    ('NA',  'Not Applicable'),
    ('P',   'Passed'),
    ('F',   'Fail'),
)

# ---------------------------------------------------------------
#
# RuleResult
#
# ---------------------------------------------------------------

class RuleResult(models.Model):
  result_value           = models.IntegerField(default=0)

  implementation_pass_fail_score  = models.DecimalField(max_digits=4, decimal_places=1, default=-1)
  implementation_score            = models.DecimalField(max_digits=4, decimal_places=1, default=-1)
  implementation_score_fail       = models.DecimalField(max_digits=4, decimal_places=1, default=-1)
  implementation_score_v          = models.DecimalField(max_digits=4, decimal_places=1, default=-1)
  implementation_score_w          = models.DecimalField(max_digits=4, decimal_places=1, default=-1)
  implementation_score_mc         = models.DecimalField(max_digits=4, decimal_places=1, default=-1)

  implementation_pass_fail_status  = models.CharField("Implementation Pass/Fail Status",  max_length=8, choices=IMPLEMENTATION_STATUS_CHOICES, default='U')
  implementation_status            = models.CharField("Implementation Status",  max_length=8, choices=IMPLEMENTATION_STATUS_CHOICES, default='U')

  manual_check_status    = models.CharField("Manual Check Status",  max_length=2, choices=MC_STATUS_CHOICES, default='NC')

  class Meta:
        abstract = True

  def reset(self):
    self.result_value = 0

    self.implementation_pass_fail_score  = -1
    self.implementation_score            = -1
    self.implementation_score_fail       = -1
    self.implementation_score_v          = -1
    self.implementation_score_w          = -1
    self.implementation_score_mc         = -1

    self.implementation_pass_fail_status  = 'U'
    self.implementation_status            = 'U'

    self.manual_check_status    = 'NC'

    self.save()


  def set_implementation_status(self, has_manual_checks):

    def set_status(score, label):
      if self.implementation_score >= 0:

        if score <= self.implementation_score:
          if has_manual_checks:
            self.implementation_status = label + "-MC"
          else:
            self.implementation_status = label

      if self.implementation_pass_fail_score >= 0:

        if score <= self.implementation_pass_fail_score:
          self.implementation_pass_fail_status = label

    self.implementation_pass_fail_status = 'NA'
    self.implementation_status = 'NA'
    set_status(   0, 'NI')
    set_status(  50, 'PI')
    set_status(  95, 'AC')
    set_status( 100, 'C')

    self.save()

  def addValueCSV(self, v, flag=True):
      s = '"' + str(v) + '"'
      if flag:
        s = ',' + s
      return s

  def toCSV(self):
      valuesCSV = ''
      valuesCSV += self.addValueCSV(self.result_value)
      valuesCSV += self.addValueCSV(self.implementation_pass_fail_score)
      valuesCSV += self.addValueCSV(self.implementation_score)
      valuesCSV += self.addValueCSV(self.implementation_score_fail)
      valuesCSV += self.addValueCSV(self.implementation_score_v)
      valuesCSV += self.addValueCSV(self.implementation_score_w)
      valuesCSV += self.addValueCSV(self.implementation_score_mc)
      valuesCSV += self.addValueCSV(self.implementation_pass_fail_status)
      valuesCSV += self.addValueCSV(self.implementation_status)
      valuesCSV += self.addValueCSV(self.manual_check_status)

      return valuesCSV

  def csvColumnHeaders(self):
      valuesCSV = ''
      valuesCSV += self.addValueCSV('Result Value')
      valuesCSV += self.addValueCSV('Implementation Score Pass/Fail')
      valuesCSV += self.addValueCSV('Implementation Score Pass')
      valuesCSV += self.addValueCSV('Implementation Score Fail')
      valuesCSV += self.addValueCSV('Implementation Score Violations')
      valuesCSV += self.addValueCSV('Implementation Score Warnings')
      valuesCSV += self.addValueCSV('Implementation Score Manual Checks')
      valuesCSV += self.addValueCSV('Implementation Pass/Fail Status')
      valuesCSV += self.addValueCSV('Implementation Status')
      valuesCSV += self.addValueCSV('Manual Check Status')

      return valuesCSV


# ---------------------------------------------------------------
#
# RuleElementResult
#
# ---------------------------------------------------------------

class RuleElementResult(RuleResult):

  rule  = models.ForeignKey(Rule, on_delete=models.SET_NULL, null=True, default=None)
  rule_required  = models.BooleanField(default=False)

  slug  = models.SlugField(max_length=32, default='', blank=True, editable=False)

  elements_violation     = models.BigIntegerField(default=0)
  elements_warning       = models.BigIntegerField(default=0)
  elements_mc_identified = models.BigIntegerField(default=0)
  elements_mc_passed     = models.BigIntegerField(default=0)
  elements_mc_failed     = models.BigIntegerField(default=0)
  elements_mc_na         = models.BigIntegerField(default=0)
  elements_passed        = models.BigIntegerField(default=0)
  elements_hidden        = models.BigIntegerField(default=0)

  class Meta:
        abstract = True

  def reset(self):

    self.elements_violation     = 0
    self.elements_warning       = 0
    self.elements_mc_identified = 0
    self.elements_mc_passed     = 0
    self.elements_mc_failed     = 0
    self.elements_mc_na         = 0
    self.elements_passed        = 0
    self.elements_hidden        = 0

    super(RuleElementResult, self).reset()

  def has_unresolved_manual_checks(self):
    return self.elements_mc_identified != (self.elements_mc_passed + self.elements_mc_failed + self.elements_mc_na)

  def calculate_implementation(self):

    self.implementation_pass_fail_score = -1
    self.implementation_score           = -1
    self.implementation_score_fail      = -1
    self.implementation_score_v         = -1
    self.implementation_score_w         = -1
    self.implementation_score_mc        = -1

    pass_fail_total = self.elements_violation + self.elements_warning + self.elements_passed + self.elements_mc_passed + self.elements_mc_failed
    mc_total = self.elements_mc_identified - self.elements_mc_passed - self.elements_mc_failed - self.elements_mc_na

    passed = self.elements_passed    + self.elements_mc_passed
    failed   = self.elements_violation + self.elements_warning + self.elements_mc_failed

    if mc_total > 0:
      total = pass_fail_total + mc_total
    else:
      total = pass_fail_total

    if pass_fail_total:
      self.implementation_pass_fail_score  =  (100 * passed) / pass_fail_total

    if total:
      self.implementation_score      =  (100 * passed) / total
      self.implementation_score_fail =  (100 * failed) / total
      self.implementation_score_v    =  (100 * self.elements_violation + self.elements_mc_failed) / total
      self.implementation_score_w    =  (100 * self.elements_warning) / total
      self.implementation_score_mc   =  (100 * mc_total) / total

    if total > 0:
      if self.elements_violation:
        self.result_value = RESULT_VALUE['VIOLATION']
      else:
        if self.elements_warning:
          self.result_value = RESULT_VALUE['WARNING']
        else:
          if mc_total:
            self.result_value = RESULT_VALUE['MANUAL_CHECK']
          else:
            self.result_value = RESULT_VALUE['PASS']
    else:
      self.result_value = RESULT_VALUE['NOT_APPLICABLE']

    self.set_implementation_status(self.has_unresolved_manual_checks())
    self.save()

    def toCSV(self):
      valuesCSV = ''
      valuesCSV += self.addValueCSV(self.elements_violation)
      valuesCSV += self.addValueCSV(self.elements_warning)
      valuesCSV += self.addValueCSV(self.elements_mc_identified)
      valuesCSV += self.addValueCSV(self.elements_mc_passed)
      valuesCSV += self.addValueCSV(self.elements_mc_failed)
      valuesCSV += self.addValueCSV(self.elements_mc_na)
      valuesCSV += self.addValueCSV(self.elements_passed)
      valuesCSV += self.addValueCSV(self.elements_hidden)

      valuesCSV += super(RuleElementResult, self).toCSV()

      return valuesCSV

    def csvColumnHeaders(self):
      valuesCSV = ''
      valuesCSV += self.addValueCSV('Element Violations')
      valuesCSV += self.addValueCSV('Element Warnings')
      valuesCSV += self.addValueCSV('Element Manual Checks Identified')
      valuesCSV += self.addValueCSV('Element Manual Checks Passed')
      valuesCSV += self.addValueCSV('Element Manual Checks Failed')
      valuesCSV += self.addValueCSV('Element Manual Checks Not Available')
      valuesCSV += self.addValueCSV('Element Passed')
      valuesCSV += self.addValueCSV('Element Hidden')

      valuesCSV += super(RuleElementResult, self).csvColumnHeaders()

      return valuesCSV

# ---------------------------------------------------------------
#
# RuleElementPageResult
#
# ---------------------------------------------------------------

class RuleElementPageResult(RuleElementResult):

  pages_violation    = models.IntegerField(default=0)
  pages_warning      = models.IntegerField(default=0)
  pages_manual_check = models.IntegerField(default=0)
  pages_passed       = models.IntegerField(default=0)
  pages_na           = models.IntegerField(default=0)

  pages_with_hidden_content  = models.BigIntegerField(default=0)

  class Meta:
        abstract = True

  def reset(self):

    self.pages_violation    = 0
    self.pages_warning      = 0
    self.pages_manual_check = 0
    self.pages_passed       = 0
    self.pages_na           = 0

    super(RuleElementPageResult, self).reset()


  def get_page_count_with_results(self):
    return self.pages_violation + self.pages_warning + self.pages_manual_check + self.pages_passed

  def toCSV(self):
    valuesCSV = ''
    valuesCSV += self.addValueCSV(self.pages_violation)
    valuesCSV += self.addValueCSV(self.pages_warning)
    valuesCSV += self.addValueCSV(self.pages_manual_check)
    valuesCSV += self.addValueCSV(self.pages_passed)
    valuesCSV += self.addValueCSV(self.pages_na)
    valuesCSV += self.addValueCSV(self.pages_with_hidden_content)

    valuesCSV += super(RuleElementPageResult, self).toCSV()

    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = ''
    valuesCSV += self.addValueCSV('Pages Violations')
    valuesCSV += self.addValueCSV('Pages Warnings')
    valuesCSV += self.addValueCSV('Pages Manual Checks')
    valuesCSV += self.addValueCSV('Pages Passed')
    valuesCSV += self.addValueCSV('Pages Not Available')
    valuesCSV += self.addValueCSV('Pages Hidden Content')

    valuesCSV += super(RuleElementPageResult, self).csvColumnHeaders()

    return valuesCSV


# ---------------------------------------------------------------
#
# RuleElementPageWebsiteResult
#
# ---------------------------------------------------------------

class RuleElementPageWebsiteResult(RuleElementPageResult):

  websites_violation    = models.IntegerField(default=0)
  websites_warning      = models.IntegerField(default=0)
  websites_manual_check = models.IntegerField(default=0)
  websites_passed       = models.IntegerField(default=0)
  websites_na           = models.IntegerField(default=0)

  websites_with_hidden_content  = models.BigIntegerField(default=0)

  class Meta:
        abstract = True

  def reset(self):

    self.websites_violation    = 0
    self.websites_warning      = 0
    self.websites_manual_check = 0
    self.websites_passed       = 0
    self.websites_na           = 0

    self.websites_with_hidden_content = 0

    super(RuleElementPageWebsiteResult, self).reset()

  def get_page_count_with_results(self):
    return self.pages_violation + self.pages_warning + self.pages_manual_check + self.pages_passed

  def add_website_rule_result(self, ws_rule_result):

    if ws_rule_result.elements_violation > 0:
      self.websites_violation += 1
    else:
      if ws_rule_result.elements_warning > 0:
        self.websites_warning += 1
      else:
        if ws_rule_result.elements_mc_identified > 0:
          self.websites_manual_check += 1
        else:
          if ws_rule_result.elements_passed > 0:
            self.websites_passed += 1
          else:
            self.websites_na += 1

    if ws_rule_result.elements_hidden > 0:
      self.websites_with_hidden_content += 1

    self.elements_violation     += ws_rule_result.elements_violation
    self.elements_warning       += ws_rule_result.elements_warning
    self.elements_mc_identified += ws_rule_result.elements_mc_identified
    self.elements_mc_passed     += ws_rule_result.elements_mc_passed
    self.elements_mc_failed     += ws_rule_result.elements_mc_failed
    self.elements_mc_na         += ws_rule_result.elements_mc_na
    self.elements_passed        += ws_rule_result.elements_passed
    self.elements_hidden        += ws_rule_result.elements_hidden

    self.pages_violation    += ws_rule_result.pages_violation
    self.pages_warning      += ws_rule_result.pages_warning
    self.pages_manual_check += ws_rule_result.pages_manual_check
    self.pages_passed       += ws_rule_result.pages_passed
    self.pages_na           += ws_rule_result.pages_na

    self.pages_with_hidden_content += ws_rule_result.pages_with_hidden_content

    self.calculate_implementation()
    self.save()

  def toCSV(self):
    valuesCSV = ''
    valuesCSV += self.addValueCSV(self.websites_violation)
    valuesCSV += self.addValueCSV(self.websites_warning)
    valuesCSV += self.addValueCSV(self.websites_manual_check)
    valuesCSV += self.addValueCSV(self.websites_passed)
    valuesCSV += self.addValueCSV(self.websites_na)
    valuesCSV += self.addValueCSV(self.websites_with_hidden_content)

    valuesCSV += super(RuleElementPageWebsiteResult, self).toCSV()

    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = ''
    valuesCSV += self.addValueCSV('Website Violations')
    valuesCSV += self.addValueCSV('Website Warnings')
    valuesCSV += self.addValueCSV('Website Manual Checks')
    valuesCSV += self.addValueCSV('Website Passed')
    valuesCSV += self.addValueCSV('Website Not Available')
    valuesCSV += self.addValueCSV('Website Hidden Content')

    valuesCSV += super(RuleElementPageWebsiteResult, self).csvColumnHeaders()

    return valuesCSV


# ---------------------------------------------------------------
#
# RuleGroupResult
#
# ---------------------------------------------------------------

class RuleGroupResult(RuleResult):
  rules_violation    = models.IntegerField(default=0)
  rules_warning      = models.IntegerField(default=0)
  rules_manual_check = models.IntegerField(default=0)
  rules_passed       = models.IntegerField(default=0)
  rules_na           = models.IntegerField(default=0)

  has_manual_checks  = models.BooleanField(default=False)

  rules_with_hidden_content = models.IntegerField(default=0)

  total_pages                   = models.IntegerField(default=0)
  implementation_summ           = models.IntegerField(default=0)

  total_pages_fail              = models.IntegerField(default=0)
  implementation_summ_fail      = models.IntegerField(default=0)

  total_pages_pass_fail         = models.IntegerField(default=0)
  implementation_pass_fail_summ = models.IntegerField(default=0)


  class Meta:
        abstract = True

  def reset(self):
    self.rules_violation    = 0
    self.rules_warning      = 0
    self.rules_manual_check = 0
    self.rules_passed       = 0
    self.rules_na           = 0

    self.has_manual_checks = False

    self.rules_with_hidden_content = 0

    self.total_pages              = 0
    self.implementation_summ      = 0

    self.total_pages_fail         = 0
    self.implementation_summ_fail = 0

    self.total_pages_pass_fail = 0
    self.implementation_pass_fail_summ = 0

    super(RuleGroupResult, self).reset()

  def add_rule_result(self, rule_result):

    if rule_result.pages_violation > 0:
      self.rules_violation += 1
    else:
      if rule_result.pages_warning > 0:
        self.rules_warning += 1
      else:
        if rule_result.pages_manual_check > 0:
          self.rules_manual_check += 1
        else:
          if rule_result.pages_passed > 0:
            self.rules_passed += 1
          else:
            self.rules_na += 1

    if rule_result.pages_with_hidden_content > 0:
      self.rules_with_hidden_content += 1

    pc = rule_result.get_page_count_with_results()

    if pc > 0:

      if rule_result.implementation_pass_fail_score >= 0:
        self.total_pages_pass_fail += pc
        self.implementation_pass_fail_summ += pc * rule_result.implementation_pass_fail_score
        self.implementation_pass_fail_score = self.implementation_pass_fail_summ / self.total_pages_pass_fail

      if rule_result.implementation_score >= 0:
        self.total_pages += pc
        self.implementation_summ  += pc * rule_result.implementation_score
        self.implementation_score  = self.implementation_summ / self.total_pages

      if rule_result.implementation_score_fail >= 0:
        self.total_pages_fail += pc
        self.implementation_summ_fail  += pc * rule_result.implementation_score_fail
        self.implementation_score_fail  = self.implementation_summ_fail / self.total_pages_fail

      self.implementation_score_mc = 100

      if rule_result.implementation_score >= 0:
        self.implementation_score_mc -= self.implementation_score

      if rule_result.implementation_score_fail >= 0:
        self.implementation_score_mc -= self.implementation_score_fail

      self.has_manual_checks = self.has_manual_checks or rule_result.has_unresolved_manual_checks()

    self.set_implementation_status(self.has_manual_checks)

    self.save()

  def toCSV(self):

    valuesCSV = self.addValueCSV(self.rules_violation)
    valuesCSV += self.addValueCSV(self.rules_warning)
    valuesCSV += self.addValueCSV(self.rules_manual_check)
    valuesCSV += self.addValueCSV(self.rules_passed)
    valuesCSV += self.addValueCSV(self.rules_na)
    valuesCSV += self.addValueCSV(self.has_manual_checks)
    valuesCSV += self.addValueCSV(self.rules_with_hidden_content)

    valuesCSV += self.addValueCSV(self.total_pages)
    valuesCSV += self.addValueCSV(self.implementation_summ)
    valuesCSV += self.addValueCSV(self.total_pages_fail)
    valuesCSV += self.addValueCSV(self.implementation_summ_fail)

    valuesCSV += self.addValueCSV(self.total_pages_pass_fail)
    valuesCSV += self.addValueCSV(self.implementation_pass_fail_summ)

    valuesCSV +=  super(RuleGroupResult, self).toCSV()

    return valuesCSV

  def csvColumnHeaders(self):

    valuesCSV = ''

    valuesCSV += self.addValueCSV('Rules Violation')
    valuesCSV += self.addValueCSV('Rules Warning')
    valuesCSV += self.addValueCSV('Rules Manual Check')
    valuesCSV += self.addValueCSV('Rules Passed')
    valuesCSV += self.addValueCSV('Rules Not Applicable')
    valuesCSV += self.addValueCSV('Has Manual Checks')
    valuesCSV += self.addValueCSV('Rules with Hidden Content')
    valuesCSV += self.addValueCSV('Total Pages')
    valuesCSV += self.addValueCSV('Implementation Summation') #Ask about this name and what it is for.
    valuesCSV += self.addValueCSV('Total Pages Failed')
    valuesCSV += self.addValueCSV('Implementation Summation Failed')
    valuesCSV += self.addValueCSV('Total Pages Pass/Failed')
    valuesCSV += self.addValueCSV('Implementation Pass/Fail Summation')

    valuesCSV +=  super(RuleGroupResult, self).csvColumnHeaders()

    return valuesCSV


# ---------------------------------------------------------------
#
# AllRuleGroupResult
#
# ---------------------------------------------------------------

class AllRuleGroupResult(RuleGroupResult):

  class Meta:
        abstract = True

  def compute_group_results(self):

      rules = Rule.objects.all()
      self.reset()

      print('      computing results for group: ' + str(self))

      for rule in rules:

        ws_results = self.ws_results.filter(page_count__gte=0)

        group_rule_result = self.get_group_rule_result(rule)

        for ws_result in ws_results:

          try:
            ws_rule_result = ws_result.ws_rule_results.get(rule=rule)
          except:
            continue

          group_rule_result.add_website_rule_result(ws_rule_result)

        self.add_rule_result(group_rule_result)

      for rc in RuleCategory.objects.all():
        group_rc_result   = self.get_group_rc_result(rc)
        group_rc_result.reset()

      for gl in Guideline.objects.all():
        group_gl_result   = self.get_group_gl_result(gl)
        group_gl_result.reset()

      for scope in RuleScope.objects.all():
        group_rs_result   = self.get_group_rs_result(scope)
        group_rs_result.reset()

      for arr in self.get_all_group_rule_results():
        gr = self.get_group_rc_result(arr.rule.category, arr)
        gr.add_rule_result(arr)

        gr = self.get_group_gl_result(arr.rule.wcag_primary.guideline, arr)
        gr.add_rule_result(arr)

        rs = self.get_group_rs_result(arr.rule.scope, arr)
        rs.add_rule_result(arr)

  def toCSV(self):
    valuesCSV = super(AllRuleGroupResult, self).toCSV()
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = super(AllRuleGroupResult, self).csvColumnHeaders()
    return valuesCSV
