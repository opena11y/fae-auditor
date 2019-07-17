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

file: auditResults/viewsCSV.py

Author: Jon Gunderson

"""

from __future__ import absolute_import

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import JsonResponse
from django.shortcuts import redirect

from django.contrib import messages

from itertools import chain

from django.urls import reverse_lazy, reverse
from django.contrib.auth.mixins import LoginRequiredMixin

from django.contrib.auth.models import User

from rules.models  import Rule
from audits.models import Audit

from .models       import AuditResult
from .models       import AuditGuidelineResult
from .models       import AuditRuleCategoryResult
from .models       import AuditRuleScopeResult
from .models       import AuditRuleResult

from userProfiles.models import UserProfile

from django.utils.http import is_safe_url
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, RedirectView

from auditGroupResults.models  import AuditGroupResult
from auditGroupResults.models  import AuditGroupRuleResult

from auditGroup2Results.models import AuditGroup2Result
from auditGroup2Results.models import AuditGroup2RuleResult

from websiteResults.models     import WebsiteResult
from websiteResults.models     import WebsiteRuleResult

from pageResults.models     import PageResult
from pageResults.models     import PageRuleResult

from ruleCategories.models import RuleCategory
from wcag20.models         import Guideline
from rules.models          import RuleScope
from contacts.models       import Announcement

def AllRulesResultViewCSV(request, result_slug, rule_grouping):
    ar = AuditResult.objects.get(slug=result_slug)

    if rule_grouping == 'gl':
        rule_grouping_label = "Guideline"
        rule_group_results = ar.audit_gl_results.all()
    else:
        if rule_grouping == 'rs':
            rule_grouping_label = "Rule Scope"
            rule_group_results = ar.audit_rs_results.all()
        else:
            rule_grouping_label = "Rule Category"
            rule_group_results = ar.audit_rc_results.all()

    content = "<pre>"
    content += '"All Rules Result View"\n'

    content += rule_group_results[0].csvColumnHeaders()
    content += '\n'

    for rgr in rule_group_results:
        content += rgr.toCSV() + "\n"

    return HttpResponse(content, content_type="text/html")


def RuleGroupResultViewCSV(request, result_slug, rule_grouping, rule_group_slug):
    ar = AuditResult.objects.get(slug=result_slug)

    if rule_grouping == 'gl':
        rule_group_label  = Guideline.objects.get(slug=rule_group_slug).title
        rule_group_result = ar.audit_gl_results.get(slug=rule_group_slug)
    else:
        if rule_grouping == 'rs':
            rule_group_label  = RuleScope.objects.get(slug=rule_group_slug).title
            rule_group_result = ar.audit_rs_results.get(slug=rule_group_slug)
        else:
            rule_group_label  = RuleCategory.objects.get(slug=rule_group_slug).title
            rule_group_result = ar.audit_rc_results.get(slug=rule_group_slug)


    content = "<pre>"
    content += '"Rule Group Result View"\n'

    content += rule_group_result.audit_rule_results.first().csvColumnHeaders()
    content += '\n'

    for rr in rule_group_result.audit_rule_results.all():
        content += rr.toCSV() + "\n"

    return HttpResponse(content, content_type="text/html")

def RuleGroupResultRuleViewCSV(request, result_slug, rule_grouping, rule_group_slug, rule_slug):

    ar  = AuditResult.objects.get(slug=result_slug)
    arr = AuditRuleResult.objects.get(audit_result=ar, slug=rule_slug)

    if rule_grouping == 'gl':
        rule_group_label    = Guideline.objects.get(slug=rule_group_slug).title
    else:
        if rule_grouping == 'rs':
            rule_group_label    = RuleScope.objects.get(slug=rule_group_slug).title
        else:
            rule_group_label    = RuleCategory.objects.get(slug=rule_group_slug).title
            rule_grouping       = 'rc'

    wsrrs  = WebsiteRuleResult.objects.filter(ws_report__audit_result=ar, slug=rule_slug)

    content = "<pre>"
    content += '"Rule Group Result View Rule"\n'

    # Check if audit has audit grouping
    if ar.audit.groups.count():
        agrrs  = AuditGroupRuleResult.objects.filter(group_result__audit_result=ar, slug=rule_slug)
        content += agrrs[0].csvColumnHeaders()
        for agrr in agrrs:
            content += agrr.toCSV()

    content += '\n'

    # Check if audit has audit sub grouping
    if ar.audit.group2s.count():
        ag2rrs = AuditGroup2RuleResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_slug)
        content += ag2rrs[0].csvColumnHeaders()
        for ag2rr in ag2rrs:
            content += ag2rr.toCSV()

    content += '\n'

    if wsrrs.count():
        content += wsrrs[0].csvColumnHeaders()
        for wsrr in wsrrs:
            content += wsrr.toCSV()

    return HttpResponse(content, content_type="text/html")
