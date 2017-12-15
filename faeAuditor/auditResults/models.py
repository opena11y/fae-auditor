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

file: auditResults/models.py

Author: Jon Gunderson

"""

from __future__ import absolute_import
from __future__ import unicode_literals

from django.db import models

from django.core.urlresolvers import reverse

from django.contrib.auth.models import User

from websiteResults.baseResults import RuleResult
from websiteResults.baseResults import RuleGroupResult

from ruleCategories.models import RuleCategory
from rulesets.models       import Ruleset
from wcag20.models         import Guideline
from rules.models          import RuleScope
from rules.models          import Rule

from audits.models     import Audit

from audits.models import DEPTH_CHOICES
from audits.models import WAIT_TIME_CHOICES
from audits.models import BROWSER_CHOICES
from audits.models import FOLLOW_CHOICES
from audits.models import MAX_PAGES_CHOICES

AUDIT_STATUS = (
    ('-', 'Created'),
    ('I', 'Initalized'),
    ('A', 'Analyzing'),
    ('C', 'Complete'),
    ('E', 'Error'),
    ('D', 'Marked for deletion'),
)

# ---------------------------------------------------------------
#
# AuditResult
#
# ---------------------------------------------------------------

class AuditResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  created  = models.DateTimeField(auto_now_add=True, editable=False)
  user     = models.ForeignKey(User)

  title    = models.CharField('Audit Result Title', max_length=512, default="")
  audit    = models.ForeignKey(Audit, related_name="audit_results", blank=True, null=True)  
  slug     = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  ruleset           = models.ForeignKey(Ruleset, on_delete=models.SET_NULL, null=True, default=2, blank=False)
  depth             = models.IntegerField(choices=DEPTH_CHOICES, default=2)
  max_pages         = models.IntegerField("Maximum Pages", choices=MAX_PAGES_CHOICES, default=200, blank=False)
  wait_time         = models.IntegerField(choices=WAIT_TIME_CHOICES, default=30000)
  browser_emulation = models.CharField("Browser Emulation", max_length=32, choices=BROWSER_CHOICES, default="Chrome") 
  follow            = models.IntegerField("Follow Links in", choices=FOLLOW_CHOICES, default=1, blank=False)

  total_pages    = models.IntegerField(default=0)
  total_websites = models.IntegerField(default=0)

  status       = models.CharField('Status',  max_length=10, choices=AUDIT_STATUS, default='-')  


  class Meta:
    verbose_name        = "Audit Result"
    verbose_name_plural = "Audit Results"

  def __unicode__(self):
      return 'Audit Results: ' + self.audit.title

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
# AuditRuleCategoryResult
#
# ---------------------------------------------------------------

class AuditRuleCategoryResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  audit_result   = models.ForeignKey(AuditResult, on_delete=models.CASCADE, related_name="audit_rc_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
  rule_category  = models.ForeignKey(RuleCategory, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Audit Rule Category Result"
    verbose_name_plural = "Audit Rule Category Results"
    ordering            = ['rule_category']


  def __unicode__(self):
      return 'Audit RC Result: ' + self.rule_category.title_plural 

  def save(self):
  
    if self.slug == '':
        self.slug = self.rule_category.category_id
      
    super(AuditRuleCategoryResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.rule_category.title   

  def get_id(self):
    return 'arcr_' + self.rule_category.id   

# ---------------------------------------------------------------
#
# AuditGuidelineResult
#
# ---------------------------------------------------------------

class AuditGuidelineResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  audit_result = models.ForeignKey(AuditResult, on_delete=models.CASCADE, related_name="audit_gl_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
  guideline    = models.ForeignKey(Guideline, on_delete=models.SET_NULL, null=True, default=None)

  class Meta:
    verbose_name        = "Audit Guideline Result"
    verbose_name_plural = "Audit Guideline Result"
    ordering = ['guideline']

  def __unicode__(self):
    return 'Audit GL Result: ' + str(self.guideline) 

  def save(self):
  
    if self.slug == '':
        self.slug = self.guideline.slug
      
    super(AuditGuidelineResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.guideline.title   

  def get_id(self):
    return 'aglr_' + self.guideline.id   

# ---------------------------------------------------------------
#
# AuditRuleScopeResult
#
# ---------------------------------------------------------------

class AuditRuleScopeResult(RuleGroupResult):
  id           = models.AutoField(primary_key=True)

  audit_result = models.ForeignKey(AuditResult, on_delete=models.CASCADE, related_name="audit_rs_results")

  slug           = models.SlugField(max_length=16, default="", blank=True, editable=False)
  rule_scope   = models.ForeignKey(RuleScope, on_delete=models.SET_NULL, null=True, default=None)  

  class Meta:
    verbose_name        = "Website Rule Scope Result"
    verbose_name_plural = "Website Rule Scope Results"
    ordering = ['-rule_scope']

  def __unicode__(self):
    return 'Audit Rule RS Result: ' + self.rule_scope.title 
  
  def save(self):
  
    if self.slug == '':
        self.slug = self.rule_scope.slug
      
    super(AuditRuleScopeResult, self).save() # Call the "real" save() method. 

  def get_title(self):
    return self.rule_scope.title   

  def get_id(self):
    return 'arsr_' + self.rule_scope.id   


# ---------------------------------------------------------------
#
# AuditRuleResultGroup
#
# ---------------------------------------------------------------

class AuditRuleResult(RuleResult):
  id          = models.AutoField(primary_key=True)

  audit_result = models.ForeignKey(AuditResult, on_delete=models.CASCADE, related_name="audit_rule_results")
 
  audit_rc_result  = models.ForeignKey(AuditRuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="audit_rule_results")
  audit_gl_result  = models.ForeignKey(AuditGuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="audit_rule_results")
  audit_rs_result  = models.ForeignKey(AuditRuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="audit_rule_results")

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
      
    super(AuditRuleResult, self).save() # Call the "real" save() method. 

