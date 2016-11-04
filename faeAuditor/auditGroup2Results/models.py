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

from django.core.urlresolvers import reverse

from audits.models  import AuditGroup2Item

from auditResults.models      import AuditResult
from auditGroupResults.models import AuditGroupResult

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
# AuditGroup2Result
#
# ---------------------------------------------------------------

class AuditGroup2Result(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  group_result   = models.ForeignKey(AuditGroupResult, related_name="group2_results")  

  group2_item     = models.ForeignKey(AuditGroup2Item)  

  slug           = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  total_pages    = models.IntegerField(default=0)
  total_websites = models.IntegerField(default=0)

  class Meta:
    verbose_name        = "Group2 Result"
    verbose_name_plural = "Group2 Results"

  def __unicode__(self):
      return 'Group2 Results: ' + self.group2_item.title

  def add_website_report(self, ws_result):
#    print('[AuditResult][add_website_report] ws_result: ' + str(ws_result))
    try:
      self.total_websites = self.total_websites + 1  
      self.total_pages    = self.total_pages + ws_result.page_count

      self.ws_results.add(ws_result)
      self.save()
    except:
      pass   

# ---------------------------------------------------------------
#
# AuditGroup2RuleCategoryResult
#
# ---------------------------------------------------------------

class AuditGroup2RuleCategoryResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  group2_result   = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_rc_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
  rule_category  = models.ForeignKey(RuleCategory, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group2 Rule Category Result"
    verbose_name_plural = "Group2 Rule Category Results"
    ordering            = ['rule_category']


  def __unicode__(self):
      return 'Group2 RC Result: ' + self.rule_category.title_plural 

  def save(self):
  
    if self.slug == '':
        self.slug = self.rule_category.category_id
      
    super(AuditGroup2RuleCategoryResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.rule_category.title   

  def get_id(self):
    return 'ag2rcr_' + self.rule_category.id   

# ---------------------------------------------------------------
#
# AuditGroup2GuidelineResult
#
# ---------------------------------------------------------------

class AuditGroup2GuidelineResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group2_result = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_gl_results")

  slug         = models.SlugField(max_length=16, default="", blank=True, editable=False)
  guideline    = models.ForeignKey(Guideline, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Group2 Guideline Result"
    verbose_name_plural = "Group2 Guideline Result"
    ordering = ['guideline']

  def __unicode__(self):
    return 'Group2 GL Result: ' + str(self.guideline) 

  def save(self):
  
    if self.slug == '':
        self.slug = self.guideline.slug
      
    super(AuditGroup2GuidelineResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.guideline.title   

  def get_id(self):
    return 'ag2glr_' + self.guideline.id   

# ---------------------------------------------------------------
#
# AuditGroup2RuleScopeResult
#
# ---------------------------------------------------------------

class AuditGroup2RuleScopeResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  group2_result = models.ForeignKey(AuditGroup2Result, on_delete=models.CASCADE, related_name="group2_rs_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
  rule_scope   = models.ForeignKey(RuleScope, on_delete=models.SET_NULL, null=True, default=None)  

  class Meta:
    verbose_name        = "Group2 Rule Scope Result"
    verbose_name_plural = "Group2 Rule Scope Results"
    ordering = ['-rule_scope']

  def __unicode__(self):
    return 'Group2 RS Result: ' + self.rule_scope.title 
  
  def save(self):
  
    if self.slug == '':
        self.slug = self.rule_scope.slug
      
    super(AuditGroup2RuleScopeResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.rule_scope.title   

  def get_id(self):
    return 'ag2rsr_' + self.rule_scope.id   


# ---------------------------------------------------------------
#
# AuditGroup2RuleResultGroup
#
# ---------------------------------------------------------------

class AuditGroup2RuleResult(RuleResult):
  id          = models.AutoField(primary_key=True)

  group2_result = models.ForeignKey(AuditGroupResult, on_delete=models.CASCADE, related_name="group2_rule_results")
 
  group2_rc_result  = models.ForeignKey(AuditGroup2RuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="group2_rule_results")
  group2_gl_result  = models.ForeignKey(AuditGroup2GuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="group2_rule_results")
  group2_rs_result  = models.ForeignKey(AuditGroup2RuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="group2_rule_results")

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
      
    super(AuditGroup2RuleResult, self).save() # Call the "real" save() method. 

