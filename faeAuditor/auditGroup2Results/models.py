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

file: auditGroup2Results/models.py

Author: Jon Gunderson

"""

from __future__ import absolute_import
from __future__ import unicode_literals

from django.db import models

from django.urls import reverse

from audits.models  import AuditGroup2Item

from auditResults.models      import AuditResult
from auditGroupResults.models import AuditGroupResult

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
# AuditGroup2Result
#
# ---------------------------------------------------------------

class AuditGroup2Result(AllRuleGroupResult):
  id             = models.AutoField(primary_key=True)

  group_result   = models.ForeignKey(AuditGroupResult, related_name="group2_results", on_delete=models.CASCADE)

  group2_item     = models.ForeignKey(AuditGroup2Item, on_delete=models.CASCADE)

  slug           = models.SlugField(max_length=64, default="none", blank=True, editable=False)

  page_count    = models.IntegerField(default=0)
  website_count = models.IntegerField(default=0)

  class Meta:
    verbose_name        = "Group2 Result"
    verbose_name_plural = "Group2 Results"
    ordering = ['group2_item__title']

  def __unicode__(self):
      return 'Group2: ' + self.group2_item.title

  def __str__(self):
      return 'Group2: ' + self.group2_item.title

  def reset(self):
    self.total_pages = 0
    self.total_websites = 0
    super(AuditGroup2Result, self).reset()

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
      return self.group2_item.title

  def get_abbrev(self):
    return self.group2_item.abbreviation

  def add_website_result(self, ws_result):
    self.ws_results.add(ws_result)
    self.save()

    self.compute_counts()

  def get_group_rule_result(self, rule):
      try:
        ag2rr = AuditGroup2RuleResult.objects.get(group2_result=self, rule=rule)
      except:
        ag2rr = AuditGroup2RuleResult(group2_result=self, rule=rule, slug=rule.slug)
        ag2rr.save()

      return ag2rr

  def get_all_group_rule_results(self):
      return self.group2_rule_results.all()

  def get_group_rc_result(self, rule_category, rule_result=False):
      try:
        ag2rcr = AuditGroup2RuleCategoryResult.objects.get(group2_result=self, rule_category=rule_category)
      except:
        ag2rcr = AuditGroup2RuleCategoryResult(group2_result=self, rule_category=rule_category, slug=rule_category.slug)
        ag2rcr.save()

      if rule_result:
        ag2rcr.group2_rule_results.add(rule_result)
        ag2rcr.save()
      return ag2rcr

  def get_group_gl_result(self, guideline, rule_result=False):
      try:
        ag2glr = AuditGroup2GuidelineResult.objects.get(group2_result=self, guideline=guideline)
      except:
        ag2glr = AuditGroup2GuidelineResult(group2_result=self, guideline=guideline, slug=guideline.slug)
        ag2glr.save()

      if rule_result:
        ag2glr.group2_rule_results.add(rule_result)
        ag2glr.save()
      return ag2glr

  def get_group_rs_result(self, rule_scope, rule_result=False):
      try:
        ag2rsr = AuditGroup2RuleScopeResult.objects.get(group2_result=self, rule_scope=rule_scope)
      except:
        ag2rsr = AuditGroup2RuleScopeResult(group2_result=self, rule_scope=rule_scope, slug=rule_scope.slug)
        ag2rsr.save()

      if rule_result:
        ag2rsr.group2_rule_results.add(rule_result)
        ag2rsr.save()
      return ag2rsr

  def website_rule_results(self, rule_slug):
    website_rule_results = []
    for wsr in self.ws_results.all():
      try:
          website_rule_results.append(wsr.ws_rule_results.get(slug=rule_slug))
      except:
        pass

    return website_rule_results

  def toCSV(self):
    valuesCSV = self.addValueCSV(self.get_title(), False)
    valuesCSV += self.addValueCSV(str(self.get_website_count()))
    valuesCSV += self.addValueCSV(str(self.get_page_count()))
    valuesCSV += super(AuditGroup2Result, self).toCSV() + "\n"
    return valuesCSV

  def csvColumnHeaders(self):
    valuesCSV = self.addValueCSV('Group2 Item Title', False)
    valuesCSV += self.addValueCSV('Websites')
    valuesCSV += self.addValueCSV('Pages')
    valuesCSV += super(AuditGroup2Result, self).csvColumnHeaders()
    valuesCSV += '\n'
    return valuesCSV


# ---------------------------------------------------------------
#
# AuditGroup2RuleCategoryResult
#
# ---------------------------------------------------------------

class AuditGroup2RuleCategoryResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  group2_result   = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_rc_results")

  slug           = models.SlugField(max_length=64, default="", blank=True, editable=False)
  rule_category  = models.ForeignKey(RuleCategory, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group2 Rule Category Result"
    verbose_name_plural = "Group2 Rule Category Results"
    ordering            = ['rule_category']


  def __unicode__(self):
      return 'Group2 RC: ' + self.group2_result.get_title()

  def __str__(self):
      return 'Group2 RC: ' + self.group2_result.get_title()

  def save(self):

    if self.slug == '':
        self.slug = self.rule_category.category_id

    super(AuditGroup2RuleCategoryResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group2_result.get_title()

  def get_abbrev(self):
    return self.group2_result.get_abbrev()

  def get_id(self):
    return 'ag2rcr_' + self.rule_category.id

  def get_page_count(self):
    return self.group2_result.get_page_count()

  def get_website_count(self):
    return self.group2_result.get_website_count()

# ---------------------------------------------------------------
#
# AuditGroup2GuidelineResult
#
# ---------------------------------------------------------------

class AuditGroup2GuidelineResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group2_result = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_gl_results")

  slug         = models.SlugField(max_length=64, default="", blank=True, editable=False)
  guideline    = models.ForeignKey(Guideline, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group2 Guideline Result"
    verbose_name_plural = "Group2 Guideline Result"
    ordering = ['guideline']

  def __unicode__(self):
    return 'Group2 GL: ' + self.group2_result.group2_item.title

  def __str__(self):
    return 'Group2 GL: ' + self.group2_result.group2_item.title

  def save(self):

    if self.slug == '':
        self.slug = self.guideline.slug

    super(AuditGroup2GuidelineResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group2_result.get_title()

  def get_abbrev(self):
    return self.group2_result.get_abbrev()

  def get_id(self):
    return 'ag2glr_' + self.guideline.id

  def get_page_count(self):
    return self.group2_result.get_page_count()

  def get_website_count(self):
    return self.group2_result.get_website_count()

# ---------------------------------------------------------------
#
# AuditGroup2RuleScopeResult
#
# ---------------------------------------------------------------

class AuditGroup2RuleScopeResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group2_result = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_rs_results")

  slug           = models.SlugField(max_length=64, default="", blank=True, editable=False)
  rule_scope   = models.ForeignKey(RuleScope, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group2 Rule Scope Result"
    verbose_name_plural = "Group2 Rule Scope Results"
    ordering = ['-rule_scope']

  def __unicode__(self):
    return 'Group2 RS: ' + self.rule_scope.title

  def __str__(self):
    return 'Group2 RS: ' + self.group2_result.group2_item.title

  def save(self):

    if self.slug == '':
        self.slug = self.rule_scope.slug

    super(AuditGroup2RuleScopeResult, self).save() # Call the "real" save() method.

  def get_title(self):
    return self.group2_result.get_title()

  def get_abbrev(self):
    return self.group2_result.get_abbrev()

  def get_id(self):
    return 'ag2rsr_' + self.rule_scope.id

  def get_page_count(self):
    return self.group2_result.get_page_count()

  def get_website_count(self):
    return self.group2_result.get_website_count()

# ---------------------------------------------------------------
#
# AuditGroup2RuleResultGroup
#
# ---------------------------------------------------------------

class AuditGroup2RuleResult(RuleElementPageWebsiteResult):
  id = models.AutoField(primary_key=True)

  group2_result = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_rule_results")

  group2_rc_result  = models.ForeignKey(AuditGroup2RuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="group2_rule_results")
  group2_gl_result  = models.ForeignKey(AuditGroup2GuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="group2_rule_results")
  group2_rs_result  = models.ForeignKey(AuditGroup2RuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="group2_rule_results")

  class Meta:
    verbose_name        = "Group2 Rule Result"
    verbose_name_plural = "Group2 Rule Results"
    ordering = ['implementation_score']

  def __unicode__(self):
    return 'Group2 Rule: ' + self.rule_scope.title

  def __str__(self):
    return 'Group2 Rule: ' + self.group2_result.group2_item.title

  def get_title(self):
    return self.group2_result.get_title()

  def get_abbrev(self):
    return self.group2_result.get_abbrev()

  def get_id(self):
    return 'ag2rrr_' + self.rule.id

  def get_page_count(self):
    return self.group2_result.get_page_count()

  def get_website_count(self):
    return self.group2_result.get_website_count()

  def save(self):

    if self.slug == '':
        self.slug = self.rule.nls_rule_id

    super(AuditGroup2RuleResult, self).save() # Call the "real" save() method.

