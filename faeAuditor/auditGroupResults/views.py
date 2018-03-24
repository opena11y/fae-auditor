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

file: auditGroupResults/views.py

Author: Jon Gunderson

"""

from __future__ import absolute_import
from django.shortcuts import render

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import JsonResponse
from django.shortcuts import redirect

from django.contrib import messages

from django.views.generic import TemplateView
from django.views.generic import CreateView
from django.views.generic import FormView
from django.views.generic import RedirectView

from django.contrib.auth.models import User

from auditResults.models       import AuditResult

from auditGroupResults.models  import AuditGroupResult
from auditGroupResults.models  import AuditGroupRuleCategoryResult
from auditGroupResults.models  import AuditGroupGuidelineResult
from auditGroupResults.models  import AuditGroupRuleScopeResult
from auditGroupResults.models  import AuditGroupRuleResult

from websiteResults.models     import WebsiteResult
from websiteResults.models     import WebsiteGuidelineResult
from websiteResults.models     import WebsiteRuleScopeResult
from websiteResults.models     import WebsiteRuleCategoryResult

from pageResults.models    import PageRuleCategoryResult
from pageResults.models    import PageGuidelineResult
from pageResults.models    import PageRuleScopeResult
from rulesets.models       import Ruleset
from userProfiles.models   import UserProfile

from ruleCategories.models import RuleCategory
from wcag20.models         import Guideline
from rules.models          import RuleScope
from contacts.models       import Announcement


from itertools import chain

from django.core.urlresolvers import reverse_lazy, reverse
from django.contrib.auth.mixins import LoginRequiredMixin

from audits.resultNavigationMixin import ResultNavigationMixin


# ==============================================================
#
# Audit Group Report Views
#
# ==============================================================

class AuditGroupsResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agrs = ar.group_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr in agrs:
            agr.title = agr.get_title
            agr.href  = reverse('audit_groups_audit_group_results', args=[result_slug, rule_grouping, agr.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group_results'] = agrs

        return context

class AuditGroupsAuditGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_audit_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsAuditGroupResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        audit_group_slug = kwargs['audit_group_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        agr = ar.group_results.get(slug=audit_group_slug)

        agr2s = agr.group2_results.all()
        wsrs  = agr.ws_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
            agr2.url   = 'audit_groups_audit_group_audit_group2_results.html'

        for wsr in wsrs:
            wsr.title = wsr.title
            wsr.url   = 'audit_groups_audit_group_website_results.html'

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['audit_group_results'] = agr2s
        context['website_results']     = wsrs

        return context

class AuditGroupsRuleGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_rule_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsRuleGroupResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        rule_group_slug  = kwargs['rule_group_slug']

        ar  = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            agrs            = AuditGroupGuidelineResult.objects.filter(group_result__audit_result=ar, slug=rule_group_slug)
            rule_group      = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                agrs        = AuditGroupRuleScopeResult.objects.filter(group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleScope.objects.get(slug=rule_group_slug)
            else:
                agrs        = AuditGroupRuleCategoryResult.objects.filter(group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleCategory.objects.get(slug=rule_group_slug)

        for agr in agrs:
            agr.title = agr.group_result.get_title()
            agr.href  = 'test.html' # reverse('audit_groups_rule_group_audit_group_results', args=[result_slug, rule_grouping, rule_group_slug, agr.slug])


        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['rule_group']          = rule_group
        context['audit_group_results'] = agrs

        return context

class AuditGroupsRuleGroupAuditGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_rule_group_audit_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsRuleGroupAuditGroupResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        rule_group_slug  = kwargs['rule_group_slug']
        audit_group_slug = kwargs['audit_group_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            argrs            = AuditGroupGuidelineResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
            rule_group       = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                argrs           = AuditGroupRuleScopeResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_group      = RuleScope.objects.get(slug=rule_group_slug)
            else:
                argrs           = AuditGroupRuleCategoryResult.objects.filter(group_result=ar, slug=rule_group_slug)
                rule_group      = RuleCategory.objects.get(slug=rule_group_slug)


        for argr in argrs:
            argr.title = argr.get_title()
            wsrgr.href  = reverse('audits_rule_group_audiresults_website', args=[result_slug, rule_grouping, rule_group_slug, wsrgr.ws_report.slug])
            if wsrgr.ws_report.group_result:
                wsrgr.group_title  = wsrgr.ws_report.group_result.group_item.title
                if wsrgr.ws_report.group2_result:
                    wsrgr.group2_title = wsrgr.ws_report.group2_result.group2_item.title


        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping
        context['rule_group']     = rule_group

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group_results'] = agrs

        return context
