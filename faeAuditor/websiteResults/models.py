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
import sys
import fnmatch
import os
from datetime import datetime

from os.path import join

from django.db import models

from future.standard_library import install_aliases
install_aliases()

from urllib.parse import urlparse
from pytz import timezone

from django.core.urlresolvers import reverse
from django.contrib.sites.models import Site
from django.contrib.auth.models import User

from django.db import models

from django.core.urlresolvers import reverse

from .baseResults import RuleResult
from .baseResults import RuleElementPageResult
from .baseResults import RuleElementResult
from .baseResults import RuleGroupResult

from auditResults.models        import AuditResult
from auditGroupResults.models   import AuditGroupResult
from auditGroup2Results.models  import AuditGroup2Result

from ruleCategories.models import RuleCategory
from rulesets.models       import Ruleset
from wcag20.models         import Guideline
from rules.models          import RuleScope
from rules.models          import Rule

from audits.models import FOLLOW_CHOICES
from audits.models import DEPTH_CHOICES
from audits.models import WAIT_TIME_CHOICES
from audits.models import MAX_PAGES_CHOICES

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

def getURLDomain(url):

  return url;

# ---------------------------------------------------------------
#
# Pages Summary Object
#
# ---------------------------------------------------------------

class PagesSummary:

  def __init__(self):

    self.pages_violation = 0
    self.pages_warning = 0
    self.pages_manual_check = 0
    self.pages_passed = 0
    self.pages_not_applicable = 0

  def update_summary(self, result):

    if result == RESULT_VALUE['VIOLATION']:
      self.pages_violation += 1
    elif result == RESULT_VALUE['WARNING']:
      self.pages_warning += 1
    elif result == RESULT_VALUE['MANUAL_CHECK']:
      self.pages_manual_check += 1
    elif result == RESULT_VALUE['PASS']:
      self.pages_passed += 1
    elif result == RESULT_VALUE['NOT_APPLICABLE']:
      self.pages_not_applicable += 1



# Create your models here.


EVAL_STATUS = (
    ('-', 'Created'),
    ('I', 'Initalized'),
    ('A', 'Analyzing'),
    ('S', 'Saving'),
    ('C', 'Complete'),
    ('E', 'Error'),
    ('D', 'Marked for deletion'),
    ('SUM', 'Archived for summary stats'),
)

LAST_REPORT_TYPE_CHOICES = (
  ('rules',   'Summary'),
  ('pages',   'All Pages'),
  ('page',    'Page')
)

LAST_VIEW_CHOICES = (
  ('rc',   'Rule Category'),
  ('gl',   'WCAG Guideline'),
  ('rs',   'Rule Scope')
)

# ---------------------------------------------------------------
#
# WebsiteResult
#
# ---------------------------------------------------------------

class WebsiteResult(RuleGroupResult):

  id    = models.AutoField(primary_key=True)

  audit_result   = models.ForeignKey(AuditResult,       related_name="ws_results")
  group_result   = models.ForeignKey(AuditGroupResult,  related_name="ws_results", null=True)
  group2_result  = models.ForeignKey(AuditGroup2Result, related_name="ws_results", null=True)

  slug  = models.SlugField(max_length=256, editable=False)

  title    = models.CharField("Title",  max_length=1024, default="", blank=False)

  url        = models.URLField("URL",      max_length=1024, default="", blank=False)
  follow     = models.IntegerField("Follow Links in", choices=FOLLOW_CHOICES, default=1, blank=False)
  depth      = models.IntegerField("Depth of Evaluation", choices=DEPTH_CHOICES, default=2, blank=False)
  max_pages  = models.IntegerField("Maximum Pages", choices=MAX_PAGES_CHOICES, default=0, blank=False)
  ruleset    = models.ForeignKey(Ruleset, on_delete=models.SET_NULL, null=True, default=2, blank=False)

  browser_emulation    = models.CharField("Browser Emulation", max_length=32, default="FIREFOX")

  wait_time            = models.IntegerField("How long to wait for website to load resources", choices=WAIT_TIME_CHOICES, default=90000)

  span_sub_domains     = models.CharField("Span Sub-Domains (space separated)",    max_length=1024, default="", blank=True)
  exclude_sub_domains  = models.CharField("Exclude Sub-Domains (space separated)", max_length=1024, default="", blank=True)
  include_domains      = models.CharField("Include Domains (space separated)",     max_length=1024, default="", blank=True)
  authorization        = models.TextField("Authentication Information",            max_length=8192, default="", blank=True)

  page_count = models.IntegerField("Number of Pages",  default=0)

  # Archiving information

  archive     = models.BooleanField(default=False)
  delete_flag = models.BooleanField(default=False)
  stats       = models.BooleanField(default=False)

  # Report History Information

  last_viewed        = models.DateTimeField(auto_now=True, editable=False)
  last_report_type   = models.CharField('Last Report Type', max_length=16, default="rules", choices=LAST_REPORT_TYPE_CHOICES)
  last_view          = models.CharField('Last Viewed', max_length=4, default="rc", choices=LAST_VIEW_CHOICES)
  last_group         = models.CharField('Last Group', max_length=32, default="")
  last_page          = models.IntegerField('Last Page Viewed', default=1)

  # fae-util and fae20 processing information

  created      = models.DateTimeField(auto_now_add=True, editable=False)
  status       = models.CharField('Status',  max_length=10, choices=EVAL_STATUS, default='-')

  # processining information
  processing_time        = models.IntegerField(default=-1)
  processed_urls_count   = models.IntegerField(default=-1)
  unprocessed_urls_count = models.IntegerField(default=-1)
  filtered_urls_count    = models.IntegerField(default=-1)

  data_dir_slug            = models.SlugField(max_length=50, editable=False)
  data_directory           = models.CharField('Data Directory',           max_length=1024, default="")
  data_property_file       = models.CharField('Property File Name',       max_length=1024, default="")
  data_authorization_file  = models.CharField('Authorization File Name',  max_length=1024, default="", blank=True)
  data_multiple_urls_file  = models.CharField('Multiple URLs File Name',  max_length=1024, default="", blank=True)

  log_file                 = models.CharField('Log file',       max_length=1024, default="")

  # Rule results summary information

  class Meta:
    verbose_name        = "Website Result"
    verbose_name_plural = "Website Results"
    ordering = ['-archive', '-created']

  def __str__(self):
    return "Website Result: " + self.title

  def group_title(self):
    if self.group_result:
      return self.group_result.group_item.title
    return ''

  def group2_title(self):
    if self.group2_result:
      return self.group2_result.group2_item.title
    return ''


  def save(self):

    if len(self.data_dir_slug) == 0:

      if self.follow == 2:

        url_parts = urlparse(self.url)

#        print('[url_parts]: ' + str(url_parts))

        try:
          if url_parts.netloc.find('www.') < 0:
            self.span_sub_domains = url_parts.netloc
          else:
            if url_parts.netloc.find('www.') == 0:
              self.span_sub_domains = url_parts.netloc[4:]
            else:
              parts = url_parts.netloc.split('www.')
              if len(parts) == 2:
                 self.span_sub_domains = parts[1]

        except:
          pass

      self.data_dir_slug = self.slug

      self.data_directory     = self.audit_result.audit_directory + "/" + self.slug
      self.data_property_file = self.data_directory + "/" +  self.data_dir_slug + ".properties"

      if len(self.authorization) > 0:
        self.data_authorization_file = self.data_directory + "/" +  self.data_dir_slug + ".authorization"
      else:
        self.data_authorization_file = ""

      self.log_file = self.data_directory + "/" +  self.data_dir_slug + ".log"

      self.status = '-'

    super(WebsiteResult, self).save() # Call the "real" save() method

  def delete_page_reports(self):
    # Delete page level results
    for pr in self.page_all_results.all():
      pr.delete()


  def delete_data_files(self):
    path = self.data_directory + '/data'
#    print('[delete_data_files]: ' + path)
    try:
      for file in os.listdir(path):
#        print('[delete_data_files][file]: ' + file)

        if fnmatch.fnmatch(file, '*.json'):
#          print('[delete_data_files][match]')
          os.remove(join(path,file))

    except:
      return False

    return True


  def set_status_initialized(self):
    self.status = 'I'
    self.save()

  def set_status_analyzing(self):
    self.status = 'A'
    self.save()

  def set_status_saving(self):
    self.status = 'S'
    self.save()

  def set_status_complete(self, save_data=False):
    # default is to delete data files
    if not save_data:
      self.delete_data_files()

    self.status = 'C'
    self.save()

    if self.title == '' and self.page_count == 1:
      try:
        self.title = str(self.page_all_results.first().title).strip()
      except:
        self.ttile = "no title"
      self.save()

    self.audit_result.check_if_audit_result_complete()

  def is_complete(self):
    return self.status == 'C'

  def set_status_error(self):
    self.delete_data_files()
    self.status = 'E'
    self.save()

    self.audit_result.check_if_audit_result_complete()

  def is_error(self):
    return self.status == 'E'

  def set_status_deleted(self):
    self.archive = False;
    self.status = 'D'
    self.save()

  def is_deleted(self):
    return self.status == 'D'

  def set_status_summary(self):
    self.status = 'SUM'
    self.delete_page_reports()
    self.save()

  def is_summary(self):
    return self.status == 'SUM'

  def get_first_page(self):
    return self.page_all_results.all()[0]

  def set_rule_numbers(self):
    ws_result = self.ws_all_results.last()
    num = 1
    for wsrr in ws_result.ws_rule_results.all():
      wsrr.rule_number = num
      wsrr.save()
      num += 1

  def set_page_numbers(self):
    num = 1
    for pr in self.page_all_results.all():
      pr.page_number = num
      pr.save()
      num += 1

  def get_title(self):
    if len(self.title):
      return self.title
    else:
      return "No title for: " + self.url

  def update_last_viewed(self):
    self.last_viewed = datetime.now()
    self.save()
#    print('[LAST_VIEWED][' +  self.title + ']: ' + str(self.last_viewed))

  def get_pages_summary(self, view=False, group=False):
      ps = PagesSummary()

      for pr in self.page_all_results.all():
        if view == 'rs':
          pr = pr.page_rs_results.get(rule_category__slug=group)
        elif view == 'gl':
          pr = pr.page_gl_results.get(guideline__slug=group)
        elif view == 'rc':
          pr = pr.page_rc_results.get(rule_category__slug=group)

        ps.update_summary(pr.result_value)

      return ps


  def get_page_count(self):
    if self.status == 'C' or self.status == 'E' or self.status == 'D':
        return self.page_count

    return self.get_processing_status().processed

  def to_json_results(self):
    tz = timezone(str(self.audit_result.user.profile.timezone))

    json = {}
    json['id']          = 'r' + str(self.id)
    json['title']       = self.title
    json['date']        = self.created.astimezone(tz)
    json['ruleset']     = self.ruleset.title
    json['ruleset_url'] = reverse('ruleset', args=[self.ruleset.slug])
    json['depth']       = self.depth
    json['url']         = self.url
    json['page_count']  = self.get_page_count()

    json['rule_results'] = []
    for rr in self.ws_rule_results.all():
      json['rule_results'].append(rr.to_json_results())

    json['page_results'] = []
    for pr in self.page_all_results.all():
      json['page_results'].append(pr.to_json_results())


    return json


  def to_json_status(self):
    tz = timezone(str(self.audit_result.user.profile.timezone))

    json = {}
    json['id']          = 'r' + str(self.id)
    json['slug']        = self.slug
    json['title']       = self.title
    json['status']      = self.status
    json['archive']     = self.archive
    json['date']        = self.created.astimezone(tz)
    json['ruleset']     = self.ruleset.title
    json['ruleset_url'] = reverse('ruleset', args=[self.ruleset.slug])
    json['report_url']  = reverse('report_rules',  args=[self.slug, 'rc'])
    json['report_page_url']  = ""
    if self.page_count > 0:
      json['report_page_url']  = reverse('report_page',  args=[self.slug, 'rc', 1])
    json['depth']       = self.depth
    json['url']         = self.url
    json['page_count']  = self.get_page_count()

    return json


  def get_processing_status(self):

    class processing_info:

       def __init__(self):
         self.status = ''
         self.url    = ''
         self.processed  = -1
         self.unprocessed = 0
         self.filtered  = 0
         self.time  = 0.0
         self.login_attempts = 0
         self.login_success  = 0
         self.login_fail     = 0

    pi = processing_info()

    fname = self.data_directory + "/data/status.txt"
#    print('[WebsiteResult][get_processing_status] ' + APP_DIR)
#    print('[WebsiteResult][get_processing_status] ' + fname)

    try:
      file = open( fname, "r")
      for line in file.readlines():
        if line.find("status=") >= 0:
          pi.status = line[7:]
        elif line.find("url=") >= 0:
          pi.url = line[4:]
        elif line.find("unprocessed=") >= 0:
          pi.unprocessed = int(line[12:])
        elif line.find("processed=") >= 0:
          pi.processed = int(line[10:])
        elif line.find("filtered=") >= 0:
          pi.filtered = int(line[9:])
        elif line.find("time=") >= 0:
          pi.time = float(line[5:])
        elif line.find("login_attempts=") >= 0:
          pi.login_attempts = int(line[15:])
        elif line.find("login_success=") >= 0:
          pi.login_success = int(line[14:])
        elif line.find("login_fail=") >= 0:
          pi.login_fail = int(line[11:])

    except:
      pi.status = "file not found"

    return pi

  def broken_urls(self):
    urls = []

    for url in self.processed_urls.all():
      if url.http_status_code != 200:
        urls.append(url)

    return urls


# ---------------------------------------------------------------
#
# ProcessedURL
#
# ---------------------------------------------------------------

class ProcessedURL(models.Model):
  processed_url_id = models.AutoField(primary_key=True)

  ws_report  = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="processed_urls")

  page_seq_num    = models.IntegerField(default=-1)

  url_requested    = models.URLField( 'Processed URL',  max_length=4096)
  url_returned     = models.URLField( 'Returned URL',   max_length=4096)
  redirect         = models.BooleanField("Server redirect", default=False)
  http_status_code = models.IntegerField('http status code')

  url_referenced   = models.URLField( 'Referenced URL', max_length=4096)

  dom_time   = models.IntegerField('Loading DOM time')
  link_time  = models.IntegerField('Retreive links tIme')
  event_time = models.IntegerField('Event time')
  eval_time  = models.IntegerField('Evaluation time')
  save_time  = models.IntegerField('Saving results time')
  total_time = models.IntegerField('Total processing time')

  class Meta:
    verbose_name        = "URL: Processed"
    verbose_name_plural = "URL: Processed"
    ordering = ['http_status_code', 'url_returned', 'total_time']

  def __unicode__(self):
    return self.url_returned + " (" + str(self.total_time) + " milliseconds)"

  def get_url_requested(self):
    if len(self.url_requested) > 50:
      return self.url_requested[:50] + '...... '
    else:
      return self.url_requested


  def get_url_returned(self):
    if len(self.url_returned) > 50:
      return self.url_returned[:50] + '...... '
    else:
      return self.url_returned

  def get_reference_url(self):
    if len(self.url_referenced) > 50:
      return self.url_referenced[:50] + '...... '
    else:
      return self.url_referenced

# ---------------------------------------------------------------
#
# UnprocessedURL
#
# ---------------------------------------------------------------

class UnprocessedURL(models.Model):
  unprocessed_url_id = models.AutoField(primary_key=True)

  ws_report  = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="unprocessed_urls")

  url             = models.URLField( 'Unprocessed URL', max_length=4096)
  url_referenced  = models.URLField( 'Referenced URL',  max_length=4096)

  dom_time   = models.IntegerField('Loading DOM time')
  link_time  = models.IntegerField('Retreive links tIme')
  event_time = models.IntegerField('Event time')
  eval_time  = models.IntegerField('Evaluation time')
  save_time  = models.IntegerField('Saving results time')
  total_time = models.IntegerField('Total processing time')

  class Meta:
    verbose_name        = "URL: Unprocessed"
    verbose_name_plural = "URL: Unprocessed"
    ordering = ['url', 'url_referenced']

  def __unicode__(self):
    return self.url + " (" + self.url_referenced + ")"

  def get_url(self):
    if len(self.url) > 50:
      return self.url[:50] + '...... '
    else:
      return self.url

  def get_reference_url(self):
    if len(self.url_referenced) > 50:
      return self.url_referenced[:50] + '...... '
    else:
      return self.url_referenced

# ---------------------------------------------------------------
#
# FilteredURL
#
# ---------------------------------------------------------------

class FilteredURL(models.Model):
  filtered_url_id = models.AutoField(primary_key=True)

  ws_report   = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="filtered_urls")

  url            = models.URLField( 'Other URL',      max_length=4096)
  url_referenced = models.URLField( 'Referenced URL', max_length=4096)

  class Meta:
    verbose_name        = "URL: Filtered"
    verbose_name_plural = "URL: Filtered"
    ordering = ['url_referenced', 'url']

  def __unicode__(self):
    return self.url

  def get_url(self):
    if len(self.url) > 50:
      return self.url[:50] + '...... '
    else:
      return self.url

  def get_domain(self):
    parsed = urlparse(self.url)

    return parsed.netloc


  def get_reference_url(self):
    if len(self.url_referenced) > 50:
      return self.url_referenced[:50] + '...... '
    else:
      return self.url_referenced



# ---------------------------------------------------------------
#
# WebsiteRuleCategoryResult
#
# ---------------------------------------------------------------

class WebsiteRuleCategoryResult(RuleGroupResult):
  id             = models.AutoField(primary_key=True)

  slug           = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  ws_report      = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="ws_rc_results")

  rule_category  = models.ForeignKey(RuleCategory, on_delete=models.SET_NULL, null=True)

  class Meta:
    verbose_name        = "Website Rule Category Result"
    verbose_name_plural = "Website Rule Category Results"
    ordering            = ['rule_category']

  def __unicode__(self):
    return self.rule_category.title_plural

  def get_title(self):
    return self.ws_report.title

  def get_group_title(self):
    return self.ws_report.group_title()

  def get_group2_title(self):
    return self.ws_report.group2_title()

  def get_page_count(self):
    return self.ws_report.get_page_count()

  def get_id(self):
    return 'wsrcr_' + self.rule_category.id



# ---------------------------------------------------------------
#
# WebsiteGuidelineResult
#
# ---------------------------------------------------------------

class WebsiteGuidelineResult(RuleGroupResult):
  id                 = models.AutoField(primary_key=True)

  ws_report           = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="ws_gl_results")

  slug  = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  guideline            = models.ForeignKey(Guideline, on_delete=models.SET_NULL, null=True)

  class Meta:
    verbose_name        = "Website Guideline Result"
    verbose_name_plural = "Website Guideline Results"
    ordering            = ['guideline']

  def __unicode__(self):
    return str(self.guideline)

  def get_title(self):
    return self.ws_report.title

  def get_group_title(self):
    return self.ws_report.group_title()

  def get_group2_title(self):
    return self.ws_report.group2_title()

  def get_page_count(self):
    return self.ws_report.get_page_count()

  def get_id(self):
    return 'wsglr_' + self.guideline.id




# ---------------------------------------------------------------
#
# WebsiteRuleScopeResult
#
# ---------------------------------------------------------------

class WebsiteRuleScopeResult(RuleGroupResult):
  id               = models.AutoField(primary_key=True)

  slug  = models.SlugField(max_length=16, default="none", blank=True, editable=False)

  ws_report        = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="ws_rs_results")

  rule_scope       = models.ForeignKey(RuleScope, on_delete=models.SET_NULL, null=True)


  class Meta:
    verbose_name        = "Website Rule Scope Result"
    verbose_name_plural = "Website Rule Scope Results"
    ordering            = ['-rule_scope']

  def __unicode__(self):
    return self.rule_scope.title

  def get_title(self):
    return self.ws_report.title

  def get_group_title(self):
    return self.ws_report.group_title()

  def get_group2_title(self):
    return self.ws_report.group2_title()

  def get_page_count(self):
    return self.ws_report.get_page_count()

  def get_id(self):
    return 'wsrsr_' + self.rule_scope.id


# ---------------------------------------------------------------
#
# WebsiteRuleResult
#
# ---------------------------------------------------------------

class WebsiteRuleResult(RuleElementPageResult):
  id            = models.AutoField(primary_key=True)

  ws_report     = models.ForeignKey(WebsiteResult, on_delete=models.CASCADE, related_name="ws_rule_results")

  ws_rc_result  = models.ForeignKey(WebsiteRuleCategoryResult, on_delete=models.SET_NULL,  null=True, related_name="ws_rule_results")
  ws_gl_result  = models.ForeignKey(WebsiteGuidelineResult,    on_delete=models.SET_NULL,  null=True, related_name="ws_rule_results")
  ws_rs_result  = models.ForeignKey(WebsiteRuleScopeResult,    on_delete=models.SET_NULL,  null=True, related_name="ws_rule_results")

  rule_number   = models.IntegerField(default=-1)

  class Meta:
    verbose_name        = "Website Rule Result"
    verbose_name_plural = "Website Rule Results"
    ordering = ['-pages_violation', '-pages_warning', '-pages_manual_check', '-pages_passed', '-pages_with_hidden_content', '-rule__scope']

  def __unicode__(self):
    return "Website Rule Result: " + self.rule.summary_text

  def get_id(self):
    return 'wsrr_' + self.rule.id

  def get_title(self):
    return self.rule.summary_text

  def to_json_results(self):
    json = {}
    json['id']        = self.rule.nls_rule_id
    json['num']       = self.rule_number
    json['summary']   = self.rule.summary_text
    json['required']  = self.rule_required
    json['rule_category']  = self.rule.category.title
    json['wcag20']         = str(self.rule.wcag_primary)
    json['scope']          = str(self.rule.scope)


    json['pages_violation']    = self.pages_violation
    json['pages_warning']      = self.pages_warning
    json['pages_manual_check'] = self.pages_manual_check
    json['pages_passed']       = self.pages_passed
    json['pages_na']           = self.pages_na

    json['elements_violation']     = self.elements_violation
    json['elements_warning']       = self.elements_warning
    json['elements_mc_identified'] = self.elements_mc_identified
    json['elements_mc_passed']     = self.elements_mc_passed
    json['elements_mc_failed']     = self.elements_mc_failed
    json['elements_mc_na']         = self.elements_mc_na
    json['elements_passed']        = self.elements_passed
    json['elements_hidden']        = self.elements_hidden

    json['pages_with_hidden_content'] = self.pages_with_hidden_content

    return json


