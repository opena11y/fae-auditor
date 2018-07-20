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

file: auditGroup2Results/views.py

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

from .models  import AuditGroup2Result
from .models  import AuditGroup2RuleCategoryResult
from .models  import AuditGroup2GuidelineResult
from .models  import AuditGroup2RuleScopeResult
from .models  import AuditGroup2RuleResult

from auditResults.models  import AuditResult
from auditResults.models  import AuditRuleCategoryResult
from auditResults.models  import AuditGuidelineResult
from auditResults.models  import AuditRuleScopeResult
from auditResults.models  import AuditRuleResult

from websiteResults.models     import WebsiteResult
from websiteResults.models     import WebsiteGuidelineResult
from websiteResults.models     import WebsiteRuleScopeResult
from websiteResults.models     import WebsiteRuleCategoryResult

from pageResults.models    import PageResult
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

class Group2ResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

class Group2ResultsAuditGroup2View(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2View, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

class Group2ResultsAuditGroup2WebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2_website.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2WebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
#            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

class Group2ResultsAuditGroup2WebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
#            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

class Group2ResultsAuditGroup2WebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2WebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
#            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

# ----------------
# Rule Group
# ----------------

class Group2RuleGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        rule_group_slug  = kwargs['rule_group_slug']

        ar  = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            argr            = AuditGuidelineResult.objects.get(audit_result=ar, slug=rule_group_slug)
            agr2s           = AuditGroup2GuidelineResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_group_slug)
            rule_group      = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                argr        = AuditRuleScopeResult.objects.get(audit_result=ar, slug=rule_group_slug)
                agr2s       = AuditGroup2RuleScopeResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleScope.objects.get(slug=rule_group_slug)
            else:
                argr        = AuditRuleCategoryResult.objects.get(audit_result=ar, slug=rule_group_slug)
                agr2s       = AuditGroup2RuleCategoryResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
            agr2.href  = reverse('group2_rule_group_results_audit_group2', args=[result_slug, rule_grouping, rule_group_slug, agr2.slug])

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']           = rule_group
        context['audit_group2_results'] = agr2s

        return context

class Group2RuleGroupResultsAuditGroup2View(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2View, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']

        ar     = AuditResult.objects.get(slug=result_slug)
        ag2r   = AuditGroup2Result.objects.get(group_result__audit_result=ar, slug=audit_group2_slug)

        if rule_grouping == 'gl':
            ag2grr          = AuditGroup2GuidelineResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
            wsrgrs          = WebsiteGuidelineResults.objects.filter(ws_report__group2_result=ag2r)
            rule_group      = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                ag2grr      = AuditGroup2RuleScopeResult.objects.filter(group2_result=ag2r, slug=rule_group_slug)
                wsrgrs      = WebsiteRuleScopeResults.objects.filter(ws_report__group2_result=ag2r)
                rule_group  = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping = 'rc'
                ag2grr      = AuditGroup2RuleCategoryResult.objects.filter(group2_result=ag2r, slug=rule_group_slug)
                wsrgrs      = WebsiteRuleCategoryResults.objects.filter(ws_report__group2_result=ag2r)
                rule_group  = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_group('', audit_group2_slug)
        self.result_nav.create_result_navigation()

        for wsrgr in wsrgrs:
            wsrgr.title = wsrgr.get_title
            wsrgr.href  = reverse('group2_rule_group_results_audit_group2_website', args=[result_slug, rule_grouping, audit_group2_slug, wsrgr.slug])

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']           = rule_group
        context['audit_group2_result']  = ag2grr
        context['website_results']      = wsrgrs


        return context

class Group2RuleGroupResultsAuditGroup2WebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2_website.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2WebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
#            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

class Group2RuleGroupResultsAuditGroup2WebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
#            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context

class Group2RuleGroupResultsAuditGroup2WebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupesultsAuditGroup2WebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        agr2s = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
#            agr2.href  = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, agr2.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_group2_results'] = agr2s

        return context
