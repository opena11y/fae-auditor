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

file: auditGroupResults/models.py

Author: Jon Gunderson

"""

from __future__ import absolute_import
from __future__ import unicode_literals

from django.db import models

from django.urls import reverse

from audits.models import AuditGroupItem

from auditResults.models import AuditResult

from websiteResults.baseResults import RuleResult
from websiteResults.baseResults import RuleElementPageResult
from websiteResults.baseResults import RuleElementPageWebsiteResult
from websiteResults.baseResults import RuleGroupResult
from websiteResults.baseResults import AllRuleGroupResult

from ruleCategories.models import RuleCategory
from rulesets.models       import Ruleset
from wcag20.models         import Guideline
from rules.models          import RuleScope
from rules.models          import Rule

from audits.models     import Audit

from audits.models import DEPTH_CHOICES
from audits.models import WAIT_TIME_CHOICES
from audits.models import BROWSER_CHOICES


# ---------------------------------------------------------------
#
# AuditGroupResult
#
# ---------------------------------------------------------------

class AuditGroupResult(AllRuleGroupResult):
  id             = models.AutoField(primary_key=True)

  audit_result   = models.ForeignKey(AuditResult, related_name="group_results", on_delete=models.CASCADE)

  group_item     = models.ForeignKey(AuditGroupItem, on_delete=models.CASCADE)

  slug           = models.SlugField(max_length=64, default="none", blank=True, editable=False)

  page_count    = models.IntegerField(default=0)
  website_count = models.IntegerField(default=0)

  class Meta:
    verbose_name        = "Group Result"
    verbose_name_plural = "Group Results"
    ordering = ['group_item']

  def __unicode__(self):
    return 'Group: ' + self.group_item.title

  def __str__(self):
    return 'Group: ' + self.group_item.title + ' (' + str(self.audit_result.created.strftime("%Y-%m-%d")) + ')'

  def reset(self):
    self.total_pages = 0
    self.total_websites = 0
    super(AuditGroupResult, self).reset()

  def get_page_count(self):
    if self.page_count == 0:
      self.website_count = 0
      for wsr in self.ws_results.all():
        self.website_count += 1
        self.page_count += wsr.get_page_count()

      self.save()

    return self.page_count

  def get_website_count(self):
    if self.website_count == 0:
      self.page_count = 0
      for wsr in self.ws_results.all():
        self.website_count += 1
        self.page_count += wsr.get_page_count()

      self.save()

    return self.website_count

  def compute_counts(self):

      self.page_count = 0
      self.website_count = 0

      for wsr in self.ws_results.all():
        self.website_count = self.website_count + 1
        self.page_count    = self.page_count + wsr.page_count

      self.save()

  def get_title(self):
    return self.group_item.title

  def get_abbrev(self):
    return self.group_item.abbreviation

  def add_website_result(self, ws_result):
    self.ws_results.add(ws_result)
    self.save()
    self.compute_counts()

  def get_group_rule_result(self, rule):
      try:
        arr = AuditGroupRuleResult.objects.get(group_result=self, rule=rule)
      except:
        arr = AuditGroupRuleResult(group_result=self, rule=rule, slug=rule.slug)
        arr.save()

      return arr

  def get_all_group_rule_results(self):
      return self.group_rule_results.all()

  def get_group_rc_result(self, rule_category, rule_result=False):
      try:
        agrcr = AuditGroupRuleCategoryResult.objects.get(group_result=self, rule_category=rule_category)
      except:
        agrcr = AuditGroupRuleCategoryResult(group_result=self, rule_category=rule_category, slug=rule_category.slug)
        agrcr.save()

      if rule_result:
        agrcr.group_rule_results.add(rule_result)
        agrcr.save()
      return agrcr

  def get_group_gl_result(self, guideline, rule_result=False):
      try:
        agglr = AuditGroupGuidelineResult.objects.get(group_result=self, guideline=guideline)
      except:
        agglr = AuditGroupGuidelineResult(group_result=self, guideline=guideline, slug=guideline.slug)
        agglr.save()

      if rule_result:
        agglr.group_rule_results.add(rule_result)
        agglr.save()
      return agglr

  def get_group_rs_result(self, rule_scope, rule_result=False):
      try:
        agrsr = AuditGroupRuleScopeResult.objects.get(group_result=self, rule_scope=rule_scope)
      except:
        agrsr = AuditGroupRuleScopeResult(group_result=self, rule_scope=rule_scope, slug=rule_scope.slug)
        agrsr.save()

      if rule_result:
        agrsr.group_rule_results.add(rule_result)
        agrsr.save()
      return agrsr

  def toCSV(self):
    valuesCSV = self.addValueCSV(self.get_title(), False)
    valuesCSV += self.addValueCSV(str(self.get_website_count()))
    valuesCSV += self.addValueCSV(str(self.get_page_count()))
    valuesCSV += super(AuditGroupResult, self).toCSV() + "\n"
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = self.addValueCSV('Group Item Title', False)
    valuesCSV += self.addValueCSV('Websites')
    valuesCSV += self.addValueCSV('Pages')
    valuesCSV += super(AuditGroupResult, self).csvColumnHeaders()
    valuesCSV += '\n'
    return valuesCSV


# ---------------------------------------------------------------
#
# AuditGroupRuleCategoryResult
#
# ---------------------------------------------------------------

class AuditGroupRuleCategoryResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  group_result   = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_rc_results")

  slug           = models.SlugField(max_length=64, default="", blank=True, editable=False)
  rule_category  = models.ForeignKey(RuleCategory, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group Rule Category Result"
    verbose_name_plural = "Group Rule Category Results"
    ordering            = ['group_result__group_item']


  def __unicode__(self):
    return 'Group RC: ' + self.group_result.group_item.title


  def __str__(self):
    return 'Group RC: ' + self.group_result.group_item.title

  def save(self):

    if self.slug == '':
        self.slug = self.rule_category.category_id

    super(AuditGroupRuleCategoryResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group_result.get_title()

  def get_abbrev(self):
    return self.group_result.get_abbrev()

  def get_id(self):
    return 'agrcr_' + self.rule_category.id

  def get_page_count(self):
    return self.group_result.get_page_count()

  def get_website_count(self):
    return self.group_result.get_website_count()

  def toCSV(self):
    valuesCSV = self.addValueCSV(self.get_title(), False)
    valuesCSV += self.addValueCSV(str(self.get_website_count()))
    valuesCSV += self.addValueCSV(str(self.get_page_count()))
    valuesCSV += super(AuditGroupRuleCategoryResult, self).toCSV() + "\n"
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = self.addValueCSV('Group Item Title', False)
    valuesCSV += self.addValueCSV('Websites')
    valuesCSV += self.addValueCSV('Pages')
    valuesCSV += super(AuditGroupRuleCategoryResult, self).csvColumnHeaders()
    valuesCSV += '\n'
    return valuesCSV

# ---------------------------------------------------------------
#
# AuditGroupGuidelineResult
#
# ---------------------------------------------------------------

class AuditGroupGuidelineResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_gl_results")

  slug         = models.SlugField(max_length=64, default="", blank=True, editable=False)
  guideline    = models.ForeignKey(Guideline, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group Guideline Result"
    verbose_name_plural = "Group Guideline Result"
    ordering = ['group_result__group_item']

  def __unicode__(self):
    return 'Group GL: ' + self.group_result.group_item.title

  def __str__(self):
    return 'Group GL: ' + self.group_result.group_item.title

  def save(self):

    if self.slug == '':
        self.slug = self.guideline.slug

    super(AuditGroupGuidelineResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group_result.get_title()

  def get_abbrev(self):
    return self.group_result.get_abbrev()

  def get_id(self):
    return 'agglr_' + self.guideline.id

  def get_page_count(self):
    return self.group_result.get_page_count()

  def get_website_count(self):
    return self.group_result.get_website_count()

  def toCSV(self):
    valuesCSV = self.addValueCSV(self.get_title(), False)
    valuesCSV += self.addValueCSV(str(self.get_website_count()))
    valuesCSV += self.addValueCSV(str(self.get_page_count()))
    valuesCSV += super(AuditGroupGuidelineResult, self).toCSV() + "\n"
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = self.addValueCSV('Group Item Title', False)
    valuesCSV += self.addValueCSV('Websites')
    valuesCSV += self.addValueCSV('Pages')
    valuesCSV += super(AuditGroupGuidelineResult, self).csvColumnHeaders()
    valuesCSV += '\n'
    return valuesCSV

# ---------------------------------------------------------------
#
# AuditGroupRuleScopeResult
#
# ---------------------------------------------------------------

class AuditGroupRuleScopeResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_rs_results")

  slug           = models.SlugField(max_length=64, default="", blank=True, editable=False)
  rule_scope   = models.ForeignKey(RuleScope, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group Rule Scope Result"
    verbose_name_plural = "Group Rule Scope Results"
    ordering = ['group_result__group_item']

  def __unicode__(self):
    return 'Group RS: ' + self.group_result.group_item.title

  def __str__(self):
    return 'Group RS: ' + self.group_result.group_item.title


  def save(self):

    if self.slug == '':
        self.slug = self.rule_scope.slug

    super(AuditGroupRuleScopeResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group_result.get_title()

  def get_abbrev(self):
    return self.group_result.get_abbrev()

  def get_id(self):
    return 'agrsr_' + self.rule_scope.id

  def get_page_count(self):
    return self.group_result.get_page_count()

  def get_website_count(self):
    return self.group_result.get_website_count()

  def toCSV(self):
    valuesCSV = self.addValueCSV(self.get_title(), False)
    valuesCSV += self.addValueCSV(str(self.get_website_count()))
    valuesCSV += self.addValueCSV(str(self.get_page_count()))
    valuesCSV += super(AuditGroupRuleScopeResult, self).toCSV() + "\n"
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = self.addValueCSV('Group Item Title', False)
    valuesCSV += self.addValueCSV('Websites')
    valuesCSV += self.addValueCSV('Pages')
    valuesCSV += super(AuditGroupRuleScopeResult, self).csvColumnHeaders()
    valuesCSV += '\n'
    return valuesCSV

# ---------------------------------------------------------------
#
# AuditGroupRuleResultGroup
#
# ---------------------------------------------------------------

class AuditGroupRuleResult(RuleElementPageWebsiteResult):
  id          = models.AutoField(primary_key=True)

  group_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_rule_results")

  group_rc_result  = models.ForeignKey(AuditGroupRuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="group_rule_results")
  group_gl_result  = models.ForeignKey(AuditGroupGuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="group_rule_results")
  group_rs_result  = models.ForeignKey(AuditGroupRuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="group_rule_results")

  class Meta:
    verbose_name        = "Group Rule Result"
    verbose_name_plural = "Group Rule Results"
    ordering = ['implementation_score']

  def __unicode__(self):
    return 'Group Rule: ' + self.group_result.group_item.title

  def __str__(self):
    return 'Group Rule: ' + self.group_result.group_item.title


  def save(self):

    if self.slug == '':
        self.slug = self.rule.nls_rule_id

    super(AuditGroupRuleResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group_result.get_title()

  def get_abbrev(self):
    return self.group_result.get_abbrev()

  def toCSV(self):
    valuesCSV = self.addValueCSV(self.get_title(), False)
    valuesCSV += super(AuditGroupRuleResult, self).toCSV() + "\n"
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = self.addValueCSV('Conference', False)
    valuesCSV += super(AuditGroupRuleResult, self).csvColumnHeaders()
    valuesCSV += '\n'
    return valuesCSV

