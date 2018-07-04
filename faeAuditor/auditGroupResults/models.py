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

from django.core.urlresolvers import reverse

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

  audit_result   = models.ForeignKey(AuditResult, related_name="group_results")

  group_item     = models.ForeignKey(AuditGroupItem)

  slug           = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  total_pages    = models.IntegerField(default=0)
  total_websites = models.IntegerField(default=0)

  class Meta:
    verbose_name        = "Group Result"
    verbose_name_plural = "Group Results"
    ordering = ['group_item']

  def __unicode__(self):
    return 'Group: ' + self.group_item.title

  def __str__(self):
    return 'Group: ' + self.group_item.title + ' (' + str(self.audit_result.created.strftime("%Y-%m-%d")) + ')'

  def get_title(self):
    return self.group_item.title

  def page_count(self):
    return self.total_pages

  def website_count(self):
    return self.total_websites

  def add_website_result(self, ws_result):
    try:
      self.total_websites = self.total_websites + 1
      self.total_pages    = self.total_pages + ws_result.page_count

      self.ws_results.add(ws_result)
      self.save()
    except:
      pass

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


# ---------------------------------------------------------------
#
# AuditGroupRuleCategoryResult
#
# ---------------------------------------------------------------

class AuditGroupRuleCategoryResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  group_result   = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_rc_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
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

  def get_id(self):
    return 'agrcr_' + self.rule_category.id

  def page_count(self):
    return self.group_result.total_pages

  def website_count(self):
    return self.group_result.total_websites

# ---------------------------------------------------------------
#
# AuditGroupGuidelineResult
#
# ---------------------------------------------------------------

class AuditGroupGuidelineResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_gl_results")

  slug         = models.SlugField(max_length=16, default="", blank=True, editable=False)
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

  def get_id(self):
    return 'agglr_' + self.guideline.id

  def page_count(self):
    return self.group_result.total_pages

  def website_count(self):
    return self.group_result.total_websites

# ---------------------------------------------------------------
#
# AuditGroupRuleScopeResult
#
# ---------------------------------------------------------------

class AuditGroupRuleScopeResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_rs_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
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

  def get_id(self):
    return 'agrsr_' + self.rule_scope.id

  def page_count(self):
    return self.group_result.total_pages

  def website_count(self):
    return self.group_result.total_websites

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

