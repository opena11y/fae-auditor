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
from datetime  import datetime

from django.core.urlresolvers import reverse

from django.contrib.auth.models import User

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

from faeAuditor.settings import APP_DIR

from audits.models import DEPTH_CHOICES
from audits.models import WAIT_TIME_CHOICES
from audits.models import BROWSER_CHOICES
from audits.models import FOLLOW_CHOICES
from audits.models import MAX_PAGES_CHOICES

AUDIT_STATUS = (
    ('-', 'Created'),
    ('I', 'Initalized'),
    ('A', 'Analyzing'),
    ('S', 'saving Group Results'),
    ('C', 'Complete'),
    ('E', 'Error'),
    ('D', 'Marked for deletion'),
)


# ---------------------------------------------------------------
#
# SummaryRuleGroup
#
# ---------------------------------------------------------------

class SummaryRuleGroup:

  def __init__(self, summary, title, items):
    self.summary = summary
    self.title   = title
    self.items   = items


# ---------------------------------------------------------------
#
# AuditResult
#
# ---------------------------------------------------------------

class AuditResult(AllRuleGroupResult):
  id             = models.AutoField(primary_key=True)

  created  = models.DateTimeField(auto_now_add=True, editable=False)
  user     = models.ForeignKey(User)

  title    = models.CharField('Audit Result Title', max_length=512, default="")
  audit    = models.ForeignKey(Audit, related_name="audit_results", blank=True, null=True)
  slug     = models.SlugField(max_length=60, default="none", blank=True)

  ruleset           = models.ForeignKey(Ruleset, on_delete=models.SET_NULL, null=True, default=2, blank=False)
  depth             = models.IntegerField(choices=DEPTH_CHOICES, default=2)
  max_pages         = models.IntegerField("Maximum Pages", choices=MAX_PAGES_CHOICES, default=200, blank=False)
  wait_time         = models.IntegerField(choices=WAIT_TIME_CHOICES, default=30000)
  browser_emulation = models.CharField("Browser Emulation", max_length=32, choices=BROWSER_CHOICES, default="Chrome")
  follow            = models.IntegerField("Follow Links in", choices=FOLLOW_CHOICES, default=1, blank=False)

  status       = models.CharField('Status',  max_length=10, choices=AUDIT_STATUS, default='-')

  audit_directory = models.CharField('Data Directory', max_length=1024, default="")

  page_count    = models.IntegerField(default=0)
  website_count = models.IntegerField(default=0)

  class Meta:
    verbose_name        = "Audit Result"
    verbose_name_plural = "Audit Results"
    ordering = ['-created']

  def __unicode__(self):
    return 'Audit: ' + self.audit.title

  def __str__(self):
    return 'Audit: ' + self.audit.title + ' (' + str(self.created.strftime("%Y-%m-%d")) + ')'

  def reset(self):
    self.total_pages = 0
    self.total_websites = 0
    super(AuditResult, self).reset()

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

  def group_title(self):
    if self.audit.groups.all().count() > 0:
      return self.audit.groups.all().first().title
    return ''

  def group_title_plural(self):
    if self.audit.groups.all().count() > 0:
      return self.audit.groups.all().first().title_plural
    return ''

  def group2_title(self):
    if self.audit.group2s.all().count() > 0:
      return self.audit.group2s.all().first().title
    return ''

  def group2_title_plural(self):
    if self.audit.group2s.all().count() > 0:
      return self.audit.group2s.all().first().title_plural
    return ''

  def save(self):
    super(AuditResult, self).save() # Call the "real" save() method

    if self.slug == 'none':
      self.slug = self.audit.slug + "-" + self.created.strftime('%Y-%m-%d')
      self.audit_directory  = APP_DIR + "data/" + self.user.username  + "/" + self.slug
      self.save()

  def add_website_result(self, ws_result):
    self.ws_results.add(ws_result)
    self.save()
    self.compute_counts()

  def get_websiteresults_initialized(self):
    count  = self.ws_results.filter(status='-').count()
    count += self.ws_results.filter(status='I').count()
    return count

  def get_websiteresults_processing(self):
    count = self.ws_results.filter(status='A').count()
    count += self.ws_results.filter(status='S').count()
    return count

  def get_websiteresults_complete(self):
    return self.ws_results.filter(status='C').count()

  def get_websiteresults_error(self):
    return self.ws_results.filter(status='E').count()

  def get_websiteresults_total(self):
    return self.ws_results.all().count()

  def check_if_audit_result_complete(self):
    if self.status != 'S' and self.status != 'C':
      if self.get_websiteresults_initialized() == 0 and self.get_websiteresults_processing() == 0:

        if self.get_websiteresults_complete() > 0:
          self.status = 'S'
        else:
          self.status = 'E'
        self.save()

      else:

        if self.get_websiteresults_processing() > 0:
          self.status = 'A'
          self.save()

      if self.status == 'S':
        self.compute_audit_results()

  def compute_audit_results(self, force=False):

    if self.status == 'S' or force:

      print(self.slug + ' (' + str(len(self.group_results.all())) + ')')

      self.compute_group_results()

      for agr in self.group_results.all():

        print('  ' + agr.slug + ' (' + str(len(agr.group2_results.all())) + ')')
        agr.compute_group_results()

        for ag2r in agr.group2_results.all():
          print('    ' + ag2r.slug)
          ag2r.compute_group_results()

      self.status = 'C'
      self.save()

  # Following functions are used in populating evaluation results

  def get_group_rule_result(self, rule):
    try:
      arr = AuditRuleResult.objects.get(audit_result=self,rule=rule)
    except:
      arr = AuditRuleResult(audit_result=self,rule=rule,slug=rule.slug)
      arr.save()

    return arr

  def get_all_group_rule_results(self):
    return self.audit_rule_results.all()

  def get_group_rc_result(self, rule_category, rule_result=False):
    try:
      arcr = AuditRuleCategoryResult.objects.get(audit_result=self, rule_category=rule_category)
    except:
      arcr = AuditRuleCategoryResult(audit_result=self, rule_category=rule_category, slug=rule_category.slug)
      arcr.save()

    if rule_result:
      arcr.audit_rule_results.add(rule_result)
      arcr.save()

    return arcr

  def get_group_gl_result(self, guideline, rule_result=False):
    try:
      aglr = AuditGuidelineResult.objects.get(audit_result=self, guideline=guideline)
    except:
      aglr = AuditGuidelineResult(audit_result=self, guideline=guideline, slug=guideline.slug)
      aglr.save()

    if rule_result:
      aglr.audit_rule_results.add(rule_result)
      aglr.save()

    return aglr

  def get_group_rs_result(self, rule_scope, rule_result=False):
    try:
      arsr = AuditRuleScopeResult.objects.get(audit_result=self,rule_scope=rule_scope)
    except:
      arsr = AuditRuleScopeResult(audit_result=self,rule_scope=rule_scope,slug=rule_scope.slug)
      arsr.save()

    if rule_result:
      arsr.audit_rule_results.add(rule_result)
      arsr.save()

    return arsr


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
    return 'Audit RC: ' + self.audit_result.audit.title

  def __str__(self):
    return 'Audit RC: ' + self.audit_result.audit.title


  def save(self):

    if self.slug == '':
        self.slug = self.rule_category.category_id

    super(AuditRuleCategoryResult, self).save() # Call the "real" save() method.

  def title(self):
    return self.rule_category.title

  def id(self):
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
    return 'Audit GL: ' + self.audit_result.audit.title

  def __str__(self):
    return 'Audit GL: ' + self.audit_result.audit.title

  def save(self):

    if self.slug == '':
        self.slug = self.guideline.slug

    super(AuditGuidelineResult, self).save() # Call the "real" save() method.

  def title(self):
    return self.guideline.title

  def id(self):
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
    verbose_name        = "Audit Rule Scope Result"
    verbose_name_plural = "Audit Rule Scope Results"
    ordering = ['-rule_scope']

  def __unicode__(self):
    return 'Audit RS: ' + self.audit_result.audit.title

  def __str__(self):
    return 'Audit RS: ' + self.audit_result.audit.title

  def save(self):

    if self.slug == '':
        self.slug = self.rule_scope.slug

    super(AuditRuleScopeResult, self).save() # Call the "real" save() method.

  def title(self):
    return self.rule_scope.title

  def id(self):
    return 'arsr_' + self.rule_scope.id


# ---------------------------------------------------------------
#
# AuditRuleResultGroup
#
# ---------------------------------------------------------------

class AuditRuleResult(RuleElementPageWebsiteResult):
  id          = models.AutoField(primary_key=True)

  audit_result = models.ForeignKey(AuditResult, on_delete=models.CASCADE, related_name="audit_rule_results")

  audit_rc_result  = models.ForeignKey(AuditRuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="audit_rule_results")
  audit_gl_result  = models.ForeignKey(AuditGuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="audit_rule_results")
  audit_rs_result  = models.ForeignKey(AuditRuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="audit_rule_results")

  class Meta:
    verbose_name        = "Audit Rule Result"
    verbose_name_plural = "Audit Rule Results"
    ordering = ['implementation_score']

  def __unicode__(self):
    return 'Audit Rule Result (' + self.slug + '): ' + self.audit_result.title

  def __str__(self):
    return 'Audit Rule Result (' + self.slug + '): ' + self.audit_result.title

  def save(self):

    if self.slug == '':
        self.slug = self.rule.rule_id

    super(AuditRuleResult, self).save() # Call the "real" save() method.

  def title(self):
    return self.rule.summary


