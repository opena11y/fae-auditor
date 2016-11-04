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

from websiteResults.models import RuleResult
from websiteResults.models import RuleGroupResult

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

class AuditGroupResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  audit_result   = models.ForeignKey(AuditResult, related_name="group_results")  

  group_item     = models.ForeignKey(AuditGroupItem)  

  slug           = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  total_pages    = models.IntegerField(default=0)
  total_websites = models.IntegerField(default=0)

  class Meta:
    verbose_name        = "Group Result"
    verbose_name_plural = "Group Results"

  def __unicode__(self):
      return 'Group Results: ' + self.group_item.title

  def add_website_report(self, ws_result):
#    print('[AuditGroupResult][add_website_report] ws_result: ' + str(ws_result))
    try:
      self.total_websites = self.total_websites + 1  
      self.total_pages    = self.total_pages + ws_result.page_count

      self.ws_results.add(ws_result)
      self.save()
    except:
      pass   

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
    ordering            = ['rule_category']


  def __unicode__(self):
      return 'Group RC Result: ' + self.rule_category.title_plural 

  def save(self):
  
    if self.slug == '':
        self.slug = self.rule_category.category_id
      
    super(AuditGroupRuleCategoryResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.rule_category.title   

  def get_id(self):
    return 'agrcr_' + self.rule_category.id   

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
    ordering = ['guideline']

  def __unicode__(self):
    return 'Group GL Result: ' + str(self.guideline) 

  def save(self):
  
    if self.slug == '':
        self.slug = self.guideline.slug
      
    super(AuditGroupGuidelineResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.guideline.title   

  def get_id(self):
    return 'agglr_' + self.guideline.id   

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
    ordering = ['-rule_scope']

  def __unicode__(self):
    return 'Group RS Result: ' + self.rule_scope.title 
  
  def save(self):
  
    if self.slug == '':
        self.slug = self.rule_scope.slug
      
    super(AuditGroupRuleScopeResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.rule_scope.title   

  def get_id(self):
    return 'agrsr_' + self.rule_scope.id   


# ---------------------------------------------------------------
#
# AuditGroupRuleResultGroup
#
# ---------------------------------------------------------------

class AuditGroupRuleResult(RuleResult):
  id          = models.AutoField(primary_key=True)

  group_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group_rule_results")
 
  group_rc_result  = models.ForeignKey(AuditGroupRuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="group_rule_results")
  group_gl_result  = models.ForeignKey(AuditGroupGuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="group_rule_results")
  group_rs_result  = models.ForeignKey(AuditGroupRuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="group_rule_results")

  slug  = models.SlugField(max_length=16, default='', blank=True, editable=False)
  rule  = models.ForeignKey(Rule, on_delete=models.SET_NULL, null=True, default=None)
  
  pages_violation    = models.IntegerField(default=0)
  pages_warning      = models.IntegerField(default=0)
  pages_manual_check = models.IntegerField(default=0)
  pages_passed       = models.IntegerField(default=0)
  pages_na           = models.IntegerField(default=0)

  pages_with_hidden_content  = models.IntegerField(default=0)

  def save(self):
  
    if self.slug == '':
        self.slug = self.rule.nls_rule_id
      
    super(AuditGroupRuleResult, self).save() # Call the "real" save() method. 

