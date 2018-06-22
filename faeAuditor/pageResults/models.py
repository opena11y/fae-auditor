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

file: pageResults/models.py

Author: Jon Gunderson

"""

from __future__ import division
from __future__ import absolute_import
from django.db import models

from ruleCategories.models import RuleCategory
from wcag20.models         import Guideline
from rules.models          import RuleScope
from rules.models          import Rule

from websiteResults.models import IMPLEMENTATION_STATUS_CHOICES

from websiteResults.models import RuleResult
from websiteResults.models import RuleElementResult
from websiteResults.models import RuleGroupResult
from websiteResults.models import WebsiteResult
from websiteResults.models import WebsiteRuleCategoryResult
from websiteResults.models import WebsiteGuidelineResult
from websiteResults.models import WebsiteRuleScopeResult
from websiteResults.models import WebsiteRuleResult

# Create your models here.



# ---------------------------------------------------------------
#
# PageResult
#
# ---------------------------------------------------------------

class PageResult(RuleGroupResult):
  id                 = models.AutoField(primary_key=True)

  ws_report        = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="page_all_results")

  # Page identification information

  page_number   = models.IntegerField(default=-1)

  url            = models.URLField( 'Page URL',           max_length=4096, default="")
  url_encoded    = models.URLField( 'Page URL (encoded)', max_length=8192, default="")
  title          = models.CharField('Page Title',         max_length=512, default="")

  class Meta:
    verbose_name        = "Page Result"
    verbose_name_plural = "Page Results"
    ordering = ['page_number']

  def __str__(self):
    return self.url

  def get_title(self):
    if len(self.title):
      return self.title
    else:
      return "No Title: " + self.url

  def get_id(self):
    return 'pr_' + str(self.id)

  def to_json_results(self):
    json = {}
    json['id']        = self.get_id()
    json['num']       = self.page_number
    json['title']     = self.title
    json['url']       = self.url

    json['rules_violation']    = self.rules_violation
    json['rules_warning']      = self.rules_warning
    json['rules_manual_check'] = self.rules_manual_check
    json['rules_passed']       = self.rules_passed
    json['rules_na']           = self.rules_na

    json['implementation_pass_fail_score'] = self.implementation_pass_fail_score
    json['implementation_score']           = self.implementation_score

    json['implementation_pass_fail_status'] = self.implementation_pass_fail_status
    json['implementation_status']           = self.implementation_status

    json['rules_with_hidden_content']    = self.rules_with_hidden_content

    return json


# ---------------------------------------------------------------
#
# PageRuleCategoryResult
#
# ---------------------------------------------------------------

class PageRuleCategoryResult(RuleGroupResult):
  id              = models.AutoField(primary_key=True)

  page_result     = models.ForeignKey(PageResult, on_delete=models.CASCADE, related_name="page_rc_results")

  slug            = models.SlugField(max_length=32, default="none", blank=True, editable=False)

  ws_rc_result    = models.ForeignKey(WebsiteRuleCategoryResult, related_name="page_rc_results", blank=True, null=True)

  rule_category   = models.ForeignKey(RuleCategory)

  class Meta:
    verbose_name        = "Page Rule Category Result"
    verbose_name_plural = "Page Rule Category Results"
    ordering            = ['rule_category']

  def __str__(self):
    return self.rule_category.title

  def get_page_number(self):
    return self.page_result.page_number

  def get_title(self):
    return self.page_result.get_title()

  def get_id(self):
    return 'prcr_' + self.id


# ---------------------------------------------------------------
#
# PageGuidelineResult
#
# ---------------------------------------------------------------

class PageGuidelineResult(RuleGroupResult):
  id                 = models.AutoField(primary_key=True)

  page_result   = models.ForeignKey(PageResult, on_delete=models.CASCADE, related_name="page_gl_results")

  slug            = models.SlugField(max_length=32, default="none", blank=True, editable=False)

  ws_gl_result  = models.ForeignKey(WebsiteGuidelineResult, related_name="page_gl_results", blank=True, null=True)

  guideline     = models.ForeignKey(Guideline)

  class Meta:
    verbose_name        = "Page Guideline Result"
    verbose_name_plural = "Page Guideline Results"
    ordering = ['guideline']

  def __str__(self):
    return str(self.guideline)

  def get_page_number(self):
    return self.page_result.page_number

  def get_title(self):
    return self.page_result.get_title()

  def get_id(self):
    return 'pglr_' + self.id

# ---------------------------------------------------------------
#
# PageRuleScopeResult
#
# ---------------------------------------------------------------

class PageRuleScopeResult(RuleGroupResult):
  id            = models.AutoField(primary_key=True)

  page_result   = models.ForeignKey(PageResult, on_delete=models.CASCADE, related_name="page_rs_results")

  slug            = models.SlugField(max_length=32, default="none", blank=True, editable=False)

  ws_rs_result  = models.ForeignKey(WebsiteRuleScopeResult, related_name="page_rs_results", blank=True, null=True)

  rule_scope    = models.ForeignKey(RuleScope)


  class Meta:
    verbose_name        = "Page Rule Scope Result"
    verbose_name_plural = "Page Rule Scope Results"
    ordering = ['-rule_scope']

  def __str__(self):
    return self.page_result.get_title()

  def get_page_number(self):
    return self.page_result.page_number

  def get_title(self):
    return self.page_result.get_title()

  def get_id(self):
    return 'prsr_' + self.id



# ---------------------------------------------------------------
#
# PageRuleResult
#
# ---------------------------------------------------------------

class PageRuleResult(RuleElementResult):
  id          = models.AutoField(primary_key=True)

  ws_rule_result  = models.ForeignKey(WebsiteRuleResult,      related_name="page_rule_results", blank=True)

  page_result     = models.ForeignKey(PageResult, on_delete=models.CASCADE, related_name="page_rule_results")
  page_rc_result  = models.ForeignKey(PageRuleCategoryResult, related_name="page_rule_results")
  page_gl_result  = models.ForeignKey(PageGuidelineResult,    related_name="page_rule_results")
  page_rs_result  = models.ForeignKey(PageRuleScopeResult,    related_name="page_rule_results")

  result_message  = models.CharField("Rule Result Message", max_length=4096, default="none")

  element_results_json   = models.TextField(default="", blank=True)

  class Meta:
    verbose_name        = "Page Rule Result"
    verbose_name_plural = "Page Rule Results"
    ordering = ['-elements_violation', '-elements_warning', '-elements_mc_identified', '-elements_passed', '-elements_hidden' ]




  def __str__(self):
    return "Page Rule Result: " + self.result_message


  def get_id(self):
    return 'prr_' + self.id






