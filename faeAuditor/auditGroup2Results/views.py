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

class AuditGroup2sResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/audit_group2s_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroup2sResultsView, self).get_context_data(**kwargs)

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

# All rule views
# ==============

class AuditGroup2sAuditGroup2ResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/audit_grou2ps_audit_group2_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroup2sAuditGroup2ResultsView, self).get_context_data(**kwargs)

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
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.create_result_navigation()

        for agr2 in agr2s:
            agr2.title = agr2.get_title
            agr2.href  = reverse('audit_groups_audit_group_audit_group2_results', args=[result_slug, rule_grouping, audit_group_slug, agr2.slug])

        for wsr in wsrs:
            wsr.title = wsr.title
            wsr.href  = reverse('audit_groups_audit_group_website_results', args=[result_slug, rule_grouping, audit_group_slug, wsr.slug])

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

# ======================
# All rule group 2 views
# ======================

class AuditGroup2sAuditGroup2AuditGroup2ResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_audit_group_audit_group2_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsAuditGroupAuditGroup2ResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        ag2r = agr.group2_results.get(slug=audit_group2_slug)
        wsrs = ag2r.ws_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.create_result_navigation()

        for wsr in wsrs:
            wsr.title = wsr.title
            wsr.href  = reverse('audit_groups_audit_group_audit_group2_website_results', args=[result_slug, rule_grouping, audit_group_slug, audit_group2_slug, wsr.slug])

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['audit_group2_slug'] = audit_group2_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['audit_group2_result'] = ag2r
        context['website_results']     = wsrs

        return context

class AuditGroupsAuditGroupAuditGroup2WebsiteResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_audit_group_audit_group2_website_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsAuditGroupAuditGroup2WebsiteResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        ag2r = agr.group2_results.get(slug=audit_group2_slug)
        wsrs = ag2r.ws_results.all()
        wsr  = wsrs.get(slug=website_slug)
        prs = wsr.page_all_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        for pr in prs:
            pr.page_num  = pr.page_number
            pr.title     = pr.get_title()
            pr.href      = reverse('audit_groups_audit_group_audit_group2_website_page_results', args=[result_slug, rule_grouping, audit_group_slug, audit_group2_slug, website_slug, pr.page_number])

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['audit_group2_result'] = ag2r
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_results']        = prs

        return context

class AuditGroupsAuditGroupAuditGroup2WebsitePageResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_audit_group_audit_group2_website_page_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsAuditGroupAuditGroup2WebsitePageResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        ag2r = agr.group2_results.get(slug=audit_group2_slug)
        wsrs = ag2r.ws_results.all()
        wsr  = wsrs.get(slug=website_slug)
        pr   = wsr.page_all_results.get(page_number=page_num)
        prrs = pr.page_rule_results.all()

        for prr in prrs:
            prr.title     = prr.rule.summary_html
            prr.href      = reverse('audit_groups_audit_group_audit_group2_website_page_results', args=[result_slug, rule_grouping, audit_group_slug, audit_group2_slug, website_slug, page_num, prr.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['audit_group2_result'] = ag2r
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_results']   = prrs

        return context

class AuditGroupsAuditGroupAuditGroup2WebsitePageRuleResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/audit_groups_audit_group_audit_group2_website_page_rule_results.html'

    def get_context_data(self, **kwargs):
        context = super(AuditGroupsAuditGroupAuditGroup2WebsitePageRuleResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']
        rule_slug         = kwargs['rule_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        ag2r = agr.group2_results.get(slug=audit_group2_slug)
        wsrs = ag2r.ws_results.all()
        wsr  = wsrs.get(slug=website_slug)
        pr   = wsr.page_all_results.get(page_number=page_num)
        prr  = pr.page_rule_results.get(slug=rule_slug)
        r    = prr.rule

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.set_rule(rule_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['audit_group2_result'] = ag2r
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context

