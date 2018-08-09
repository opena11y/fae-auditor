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

from .models  import AuditGroupResult
from .models  import AuditGroupRuleCategoryResult
from .models  import AuditGroupGuidelineResult
from .models  import AuditGroupRuleScopeResult
from .models  import AuditGroupRuleResult

from auditResults.models  import AuditResult
from auditResults.models  import AuditRuleCategoryResult
from auditResults.models  import AuditGuidelineResult
from auditResults.models  import AuditRuleScopeResult
from auditResults.models  import AuditRuleResult

from auditGroup2Results.models  import AuditGroup2Result
from auditGroup2Results.models  import AuditGroup2RuleCategoryResult
from auditGroup2Results.models  import AuditGroup2GuidelineResult
from auditGroup2Results.models  import AuditGroup2RuleScopeResult
from auditGroup2Results.models  import AuditGroup2RuleResult

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

class GroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsView, self).get_context_data(**kwargs)

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
            agr.title = agr.get_title()
            agr.href  = reverse('group_results_audit_group', args=[result_slug, rule_grouping, agr.slug])

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

class GroupResultsAuditGroupView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        audit_group_slug = kwargs['audit_group_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        agr = ar.group_results.get(slug=audit_group_slug)

        ag2rs = agr.group2_results.all()
        wsrs  = agr.ws_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.create_result_navigation()

        for ag2r in ag2rs:
            ag2r.title         = ag2r.get_title
            ag2r.website_count = ag2r.get_website_count()
            ag2r.page_count    = ag2r.get_page_count()
            ag2r.href          = reverse('group_results_audit_group_audit_group2', args=[result_slug, rule_grouping, audit_group_slug, ag2r.slug])

        for wsr in wsrs:
            wsr.title = wsr.title
            wsr.href  = reverse('group_results_audit_group_website', args=[result_slug, rule_grouping, audit_group_slug, wsr.slug])

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
        context['audit_group_results'] = ag2rs
        context['website_results']     = wsrs

        return context

# ======================
# All rule group 2 views
# ======================

class GroupResultsAuditGroupAuditGroup2View(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_audit_group2.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupAuditGroup2View, self).get_context_data(**kwargs)

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
            wsr.href  = reverse('group_results_audit_group_audit_group2_website', args=[result_slug, rule_grouping, audit_group_slug, audit_group2_slug, wsr.slug])

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

class GroupResultsAuditGroupAuditGroup2WebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_audit_group2_website.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupAuditGroup2WebsiteView, self).get_context_data(**kwargs)

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
            pr.href      = reverse('group_results_audit_group_audit_group2_website_page', args=[result_slug, rule_grouping, audit_group_slug, audit_group2_slug, website_slug, pr.page_number])

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

class GroupResultsAuditGroupAuditGroup2WebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_audit_group2_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

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
            prr.href      = reverse('group_results_audit_group_audit_group2_website_page_rule', args=[result_slug, rule_grouping, audit_group_slug, audit_group2_slug, website_slug, page_num, prr.slug])

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

class GroupResultsAuditGroupAuditGroup2WebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_audit_group2_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupAuditGroup2WebsitePageRuleView, self).get_context_data(**kwargs)

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
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = prr.rule


        return context

# ======================
# All rule website views
# ======================

class GroupResultsAuditGroupWebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_website.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupWebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        audit_group_slug = kwargs['audit_group_slug']
        website_slug     = kwargs['website_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        wsrs = agr.ws_results.all()
        wsr  = wsrs.get(slug=website_slug)
        prs  = wsr.page_all_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        for pr in prs:
            pr.page_num  = pr.page_number
            pr.title     = pr.get_title()
            pr.href      = reverse('group_results_audit_group_website_page', args=[result_slug, rule_grouping, audit_group_slug, website_slug, pr.page_number])

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_results']        = prs

        return context

class GroupResultsAuditGroupWebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupWebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        audit_group_slug = kwargs['audit_group_slug']
        website_slug     = kwargs['website_slug']
        page_num         = kwargs['page_num']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        wsrs = agr.ws_results.all()
        wsr  = wsrs.get(slug=website_slug)
        pr   = wsr.page_all_results.get(page_number=page_num)
        prrs = pr.page_rule_results.all()

        for prr in prrs:
            prr.title     = prr.rule.summary_html
            prr.href      = reverse('group_results_audit_group_website_page_rule', args=[result_slug, rule_grouping, audit_group_slug, website_slug, page_num, prr.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_results']   = prrs

        return context

class GroupResultsAuditGroupWebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_results_audit_group_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(GroupResultsAuditGroupWebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        audit_group_slug = kwargs['audit_group_slug']
        website_slug     = kwargs['website_slug']
        page_num         = kwargs['page_num']
        rule_slug        = kwargs['rule_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        wsrs = agr.ws_results.all()
        wsr  = wsrs.get(slug=website_slug)
        pr   = wsr.page_all_results.get(page_number=page_num)
        prr  = pr.page_rule_results.get(slug=rule_slug)
        r    = prr.rule

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.set_rule(rule_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context

# ================
# Rule Group Views
# ================

class GroupRuleGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        rule_group_slug  = kwargs['rule_group_slug']

        ar  = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            argr            = AuditGuidelineResult.objects.get(audit_result=ar, slug=rule_group_slug)
            agrs            = AuditGroupGuidelineResult.objects.filter(group_result__audit_result=ar, slug=rule_group_slug)
            rule_group      = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                argr        = AuditRuleScopeResult.objects.get(audit_result=ar, slug=rule_group_slug)
                agrs        = AuditGroupRuleScopeResult.objects.filter(group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleScope.objects.get(slug=rule_group_slug)
            else:
                argr        = AuditRuleCategoryResult.objects.get(audit_result=ar, slug=rule_group_slug)
                agrs        = AuditGroupRuleCategoryResult.objects.filter(group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleCategory.objects.get(slug=rule_group_slug)

        for agr in agrs:
            agr.title = agr.group_result.get_title()
            agr.href  = reverse('group_rule_group_results_audit_group', args=[result_slug, rule_grouping, rule_group_slug, agr.group_result.slug])

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
        context['rule_group_result']   = argr
        context['audit_group_results'] = agrs

        return context


class GroupRuleGroupResultsAuditGroupView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        rule_group_slug  = kwargs['rule_group_slug']
        audit_group_slug = kwargs['audit_group_slug']

        ar  = AuditResult.objects.get(slug=result_slug)
        agr = AuditGroupResult.objects.get(audit_result=ar, slug=audit_group_slug)

        if rule_grouping == 'gl':
            agrgr       = AuditGroupGuidelineResult.objects.get(group_result=agr, slug=rule_group_slug)
            ag2rgrs     = AuditGroup2GuidelineResult.objects.filter(group2_result__group_result=agr, slug=rule_group_slug)
            wsrgrs      = WebsiteGuidelineResult.objects.filter(ws_report__group_result=agr, slug=rule_group_slug)
            rule_group  = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                agrgr      = AuditGroupRuleScopeResult.objects.get(group_result=agr, slug=rule_group_slug)
                ag2rgrs    = AuditGroup2RuleScopeResult.objects.filter(group2_result__group_result=agr, slug=rule_group_slug)
                wsrgrs     = WebsiteRuleScopeResult.objects.filter(ws_report__group_result=agr, slug=rule_group_slug)
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                agrgr      = AuditGroupRuleCategoryResult.objects.get(group_result=agr, slug=rule_group_slug)
                ag2rgrs    = AuditGroup2RuleCategoryResult.objects.filter(group2_result__group_result=agr, slug=rule_group_slug)
                wsrgrs     = WebsiteRuleCategoryResult.objects.filter(ws_report__group_result=agr, slug=rule_group_slug)
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for ag2rgr in ag2rgrs:
            ag2rgr.title         = ag2rgr.get_title()
            ag2rgr.website_count = ag2rgr.get_website_count()
            ag2rgr.page_count    = ag2rgr.get_page_count()
            ag2rgr.href  = reverse('group_rule_group_results_audit_group_audit_group2', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, ag2rgr.group2_result.slug])

        for wsrgr in wsrgrs:
            wsrgr.title        = wsrgr.get_title()
            wsrgr.group_title  = wsrgr.get_group_title()
            wsrgr.group2_title = wsrgr.get_group2_title()
            wsrgr.page_count   = wsrgr.get_page_count()
            wsrgr.href  = reverse('group_rule_group_results_audit_group_website', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, wsrgr.ws_report.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']       = ar.audit.slug
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group_slug']  = rule_group_slug
        context['audit_group_slug'] = audit_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_group_results'] = ag2rgrs
        context['audit_group_result']  = agrgr
        context['website_results']     = wsrgrs

        return context

# =================================
# Rule grouping audit group 2 views
# =================================

class GroupRuleGroupResultsAuditGroupAuditGroup2View(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_audit_group2.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupAuditGroup2View, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = AuditGroupResult.objects.get(audit_result=ar, slug=audit_group_slug)
        ag2r = AuditGroup2Result.objects.get(group_result=agr, slug=audit_group2_slug)

        if rule_grouping == 'gl':
            ag2rgr      = AuditGroup2GuidelineResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
            wsrgrs      = WebsiteGuidelineResult.objects.filter(ws_report__group2_result=ag2r, slug=rule_group_slug)
            rule_group  = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                ag2rgr     = AuditGroup2RuleScopeResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
                wsrgrs     = WebsiteRuleScopeResult.objects.filter(ws_report__group2_result=ag2r, slug=rule_group_slug)
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                ag2rgr     = AuditGroup2RuleCategoryResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
                wsrgrs     = WebsiteRuleCategoryResult.objects.filter(ws_report__group2_result=ag2r, slug=rule_group_slug)
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for wsrgr in wsrgrs:
            wsrgr.title = wsrgr.get_title()
            wsrgr.group_title  = wsrgr.get_group_title()
            wsrgr.group2_title = wsrgr.get_group2_title()
            wsrgr.page_count   = wsrgr.get_page_count()
            wsrgr.href  = reverse('group_rule_group_results_audit_group_audit_group2_website', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, audit_group2_slug, wsrgr.ws_report.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']       = ar.audit.slug
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group_slug']  = rule_group_slug
        context['audit_group_slug'] = audit_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_group_result']   = agr
        context['audit_group2_result']  = ag2rgr
        context['website_results']      = wsrgrs

        return context


class GroupRuleGroupResultsAuditGroupAuditGroup2WebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_audit_group2_website.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupAuditGroup2WebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug = kwargs['website_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = AuditGroupResult.objects.get(audit_result=ar, slug=audit_group_slug)
        ag2r = AuditGroup2Result.objects.get(group_result=agr, slug=audit_group2_slug)
        wsr  = WebsiteResult.objects.get(group_result=agr, slug=website_slug)

        if rule_grouping == 'gl':
            wsrgr      = wsr.ws_gl_results.get(slug=rule_group_slug)
            pgrgrs     = wsrgr.page_gl_results.all()
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                wsrgr     = wsr.ws_rs_results.get(slug=rule_group_slug)
                pgrgrs     = wsrgr.page_rs_results.all()
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                wsrgr     = wsr.ws_rc_results.get(slug=rule_group_slug)
                pgrgrs     = wsrgr.page_rc_results.all()
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for pgrgr in pgrgrs:
            pgrgr.title    = pgrgr.get_title()
            pgrgr.page_num = pgrgr.get_page_number()
            pgrgr.href     = reverse('group_rule_group_results_audit_group_audit_group2_website_page', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, audit_group2_slug, website_slug, pgrgr.get_page_number()])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['rule_group_slug']   = rule_group_slug
        context['audit_group_slug']  = audit_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_group_result']   = agr
        context['audit_group2_result']  = ag2r
        context['website_result']       = wsr
        context['page_results']         = pgrgrs

        return context

class GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_audit_group2_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group_slug  = kwargs['audit_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = AuditGroupResult.objects.get(audit_result=ar, slug=audit_group_slug)
        ag2r = AuditGroup2Result.objects.get(group_result=agr, slug=audit_group2_slug)
        wsr  = WebsiteResult.objects.get(group_result=agr, slug=website_slug)
        pgr  = PageResult.objects.get(ws_report=wsr, page_number=page_num)

        if rule_grouping == 'gl':
            pgrg       = pgr.page_gl_results.get(slug=rule_group_slug)
            pgrrs      = pgrg.page_rule_results.all()
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                pgrg       = pgr.page_rs_results.get(slug=rule_group_slug)
                pgrrs      = pgrg.page_rule_results.all()
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                pgrg       = pgr.page_rc_results.get(slug=rule_group_slug)
                pgrrs      = pgrg.page_rule_results.all()
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for pgrr in pgrrs:
            pgrr.title  = pgrr.rule.summary_html
            pgrr.href   = reverse('group_rule_group_results_audit_group_audit_group2_website_page_rule', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, audit_group2_slug, website_slug, page_num, pgrr.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug, audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['rule_group_slug']   = rule_group_slug
        context['audit_group_slug']  = audit_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_group_result']   = agr
        context['audit_group2_result']  = ag2r
        context['website_result']       = wsr
        context['page_result']          = pgr
        context['page_rule_results']    = pgrrs

        return context

class GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_audit_group2_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile   = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
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

        if rule_grouping == 'gl':
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
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

        context['rule_group']    = rule_group

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['audit_group2_result'] = ag2r
        context['website_results']     = wsrs
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context


# ===========================
# Rule grouping website views
# ===========================

class GroupRuleGroupResultsAuditGroupWebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_website.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupWebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group_slug  = kwargs['audit_group_slug']
        website_slug      = kwargs['website_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = AuditGroupResult.objects.get(audit_result=ar, slug=audit_group_slug)
        wsr  = WebsiteResult.objects.get(group_result=agr, slug=website_slug)

        if rule_grouping == 'gl':
            wsrgr      = wsr.ws_gl_results.get(slug=rule_group_slug)
            pgrgrs     = wsrgr.page_gl_results.all()
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                wsrgr     = wsr.ws_rs_results.get(slug=rule_group_slug)
                pgrgrs     = wsrgr.page_rs_results.all()
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                wsrgr     = wsr.ws_rc_results.get(slug=rule_group_slug)
                pgrgrs     = wsrgr.page_rc_results.all()
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for pgrgr in pgrgrs:
            pgrgr.title    = pgrgr.get_title()
            pgrgr.page_num = pgrgr.get_page_number()
            pgrgr.href     = reverse('group_rule_group_results_audit_group_website_page', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, website_slug, pgrgr.get_page_number()])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']       = ar.audit.slug
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group_slug']  = rule_group_slug
        context['audit_group_slug'] = audit_group_slug
        context['website_slug']     = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_group_result']   = agr
        context['website_result']       = wsr
        context['page_results']         = pgrgrs

        return context


class GroupRuleGroupResultsAuditGroupWebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupWebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group_slug  = kwargs['audit_group_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = AuditGroupResult.objects.get(audit_result=ar, slug=audit_group_slug)
        wsr  = WebsiteResult.objects.get(group_result=agr, slug=website_slug)
        pgr  = PageResult.objects.get(ws_report=wsr, page_number=page_num)

        if rule_grouping == 'gl':
            pgrg       = pgr.page_gl_results.get(slug=rule_group_slug)
            pgrrs      = pgrg.page_rule_results.all()
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                pgrg       = pgr.page_rs_results.get(slug=rule_group_slug)
                pgrrs      = pgrg.page_rule_results.all()
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                pgrg       = pgr.page_rc_results.get(slug=rule_group_slug)
                pgrrs      = pgrg.page_rule_results.all()
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for pgrr in pgrrs:
            pgrr.title  = pgrr.rule.summary_html
            pgrr.href   = reverse('group_rule_group_results_audit_group_website_page_rule', args=[result_slug, rule_grouping, rule_group_slug, audit_group_slug, website_slug, page_num, pgrr.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.set_website_page(website_slug, page_num)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']       = ar.audit.slug
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group_slug']  = rule_group_slug
        context['audit_group_slug'] = audit_group_slug
        context['website_slug']     = website_slug
        context['page_num']         = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_group_result']   = agr
        context['website_result']       = wsr
        context['page_result']          = pgr
        context['page_rule_results']    = pgrrs

        return context

class GroupRuleGroupResultsAuditGroupWebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroupResults/group_rule_group_results_audit_group_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(GroupRuleGroupResultsAuditGroupWebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group_slug  = kwargs['audit_group_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']
        rule_slug         = kwargs['rule_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        agr  = ar.group_results.get(slug=audit_group_slug)
        wsr  = WebsiteResult.objects.get(group_result=agr, slug=website_slug)
        pr   = wsr.page_all_results.get(page_number=page_num)
        prr  = pr.page_rule_results.get(slug=rule_slug)
        r    = prr.rule

        if rule_grouping == 'gl':
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups(audit_group_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.set_rule(rule_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group_slug']  = audit_group_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num
        context['rule_slug']         = rule_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']    = rule_group

        context['audit_result']        = ar
        context['audit_group_result']  = agr
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context

