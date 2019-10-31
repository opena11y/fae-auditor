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

from ruleCategories.models import RuleCategory
from wcag20.models         import Guideline
from rules.models          import RuleScope
from contacts.models       import Announcement


from itertools import chain

from django.urls import reverse_lazy, reverse
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

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        ag2rs = AuditGroup2Result.objects.filter(group_result__audit_result=ar)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        for ag2r in ag2rs:
            ag2r.title         = ag2r.get_title()
            ag2r.website_count = ag2r.get_website_count()
            ag2r.page_count    = ag2r.get_page_count()
            ag2r.href          = reverse('group2_results_audit_group2', args=[result_slug, rule_grouping, ag2r.slug])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['audit_group2_results'] = ag2rs

        return context

class Group2ResultsAuditGroup2View(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2View, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group2_slug = kwargs['audit_group2_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        ag2rs = AuditGroup2Result.objects.filter(group_result__audit_result=ar)
        ag2r  = ag2rs.get(slug=audit_group2_slug)
        wsrs  = ag2r.ws_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.create_result_navigation()

        for wsr in wsrs:
            wsr.title = wsr.get_title()
            wsr.href  = reverse('group2_results_audit_group2_website', args=[result_slug, rule_grouping, audit_group2_slug, wsr.slug])

        # slugs used for urls
        context['audit_slug']         = ar.audit.slug
        context['result_slug']        = result_slug
        context['rule_grouping']      = rule_grouping
        context['audit_group2_slug']  = audit_group2_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['audit_group2_result']  = ag2r
        context['website_results']      = wsrs

        return context

class Group2ResultsAuditGroup2WebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2_website.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2WebsiteView, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        ag2rs = AuditGroup2Result.objects.filter(group_result__audit_result=ar)
        ag2r  = ag2rs.get(slug=audit_group2_slug)
        wsr   = ag2r.ws_results.get(slug=website_slug)
        prs   = wsr.page_all_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        for pr in prs:
            pr.page_num  = pr.page_number
            pr.title     = pr.get_title()
            pr.href      = reverse('group2_results_audit_group2_website_page', args=[result_slug, rule_grouping, audit_group2_slug, website_slug, pr.page_number])

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['audit_group2_result'] = ag2r
        context['website_result']      = wsr
        context['page_results']        = prs

        return context

class Group2ResultsAuditGroup2WebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']

        ar = AuditResult.objects.get(slug=result_slug)

        ag2rs = AuditGroup2Result.objects.filter(group_result__audit_result=ar)
        ag2r  = ag2rs.get(slug=audit_group2_slug)
        wsr   = ag2r.ws_results.get(slug=website_slug)
        pr    = wsr.page_all_results.get(page_number=page_num)
        prrs  = pr.page_rule_results.all()

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.create_result_navigation()

        for prr in prrs:
            prr.title     = prr.rule.summary_html
            prr.href      = reverse('group2_results_audit_group2_website_page_rule', args=[result_slug, rule_grouping, audit_group2_slug, website_slug, page_num, prr.slug])


        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['audit_group2_result']  = ag2r
        context['website_result']       = wsr
        context['page_result']          = pr
        context['page_rule_results']    = prrs

        return context

class Group2ResultsAuditGroup2WebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_results_audit_group2_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(Group2ResultsAuditGroup2WebsitePageRuleView, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']
        rule_slug         = kwargs['rule_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        ag2rs = AuditGroup2Result.objects.filter(group_result__audit_result=ar)
        ag2r  = ag2rs.get(slug=audit_group2_slug)
        wsr   = ag2r.ws_results.get(slug=website_slug)
        pr    = wsr.page_all_results.get(page_number=page_num)
        prr   = pr.page_rule_results.get(slug=rule_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.set_rule(rule_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num
        context['rule_slug']         = rule_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['audit_group2_result'] = ag2r
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = prr.rule

        return context

# ----------------
# Rule Group
# ----------------

class Group2RuleGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsView, self).get_context_data(**kwargs)

        result_slug      = kwargs['result_slug']
        rule_grouping    = kwargs['rule_grouping']
        rule_group_slug  = kwargs['rule_group_slug']

        ar  = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            argr            = AuditGuidelineResult.objects.get(audit_result=ar, slug=rule_group_slug)
            ag2rs           = AuditGroup2GuidelineResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_group_slug)
            rule_group      = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                argr        = AuditRuleScopeResult.objects.get(audit_result=ar, slug=rule_group_slug)
                ag2rs       = AuditGroup2RuleScopeResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleScope.objects.get(slug=rule_group_slug)
            else:
                argr        = AuditRuleCategoryResult.objects.get(audit_result=ar, slug=rule_group_slug)
                ag2rs       = AuditGroup2RuleCategoryResult.objects.filter(group2_result__group_result__audit_result=ar, slug=rule_group_slug)
                rule_group  = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.create_result_navigation()

        for ag2r in ag2rs:
            ag2r.title         = ag2r.get_title
            ag2r.website_count = ag2r.get_website_count()
            ag2r.page_count    = ag2r.get_page_count()

            ag2r.href  = reverse('group2_rule_group_results_audit_group2', args=[result_slug, rule_grouping, rule_group_slug, ag2r.group2_result.slug])

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['rule_group']           = rule_group
        context['audit_group2_results'] = ag2rs

        return context

class Group2RuleGroupResultsAuditGroup2View(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2View, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']

        ar    = AuditResult.objects.get(slug=result_slug)
        ag2rs = AuditGroup2Result.objects.filter(group_result__audit_result=ar)
        ag2r  = ag2rs.get(slug=audit_group2_slug)

        if rule_grouping == 'gl':
            ag2grr          = AuditGroup2GuidelineResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
            wsrgrs          = WebsiteGuidelineResult.objects.filter(ws_report__group2_result=ag2r, slug=rule_group_slug)
            rule_group      = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                ag2grr      = AuditGroup2RuleScopeResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
                wsrgrs      = WebsiteRuleScopeResult.objects.filter(ws_report__group2_result=ag2r, slug=rule_group_slug)
                rule_group  = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping = 'rc'
                ag2grr      = AuditGroup2RuleCategoryResult.objects.get(group2_result=ag2r, slug=rule_group_slug)
                wsrgrs      = WebsiteRuleCategoryResult.objects.filter(ws_report__group2_result=ag2r, slug=rule_group_slug)
                rule_group  = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.create_result_navigation()

        for wsrgr in wsrgrs:
            wsrgr.title        = wsrgr.get_title()
            wsrgr.group_title  = wsrgr.get_group_title()
            wsrgr.group2_title = wsrgr.get_group2_title()
            wsrgr.page_count   = wsrgr.get_page_count()
            wsrgr.href         = reverse('group2_rule_group_results_audit_group2_website', args=[result_slug, rule_grouping, rule_group_slug, audit_group2_slug, wsrgr.ws_report.slug])

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['rule_group_slug']   = rule_group_slug
        context['audit_group2_slug'] = audit_group2_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['rule_group']           = rule_group
        context['audit_group2_result']  = ag2grr
        context['website_results']      = wsrgrs


        return context

class Group2RuleGroupResultsAuditGroup2WebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2_website.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2WebsiteView, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        ag2r = AuditGroup2Result.objects.get(group_result__audit_result=ar, slug=audit_group2_slug)
        wsr  = WebsiteResult.objects.get(group2_result=ag2r, slug=website_slug)

        if rule_grouping == 'gl':
            wsrgr      = wsr.ws_gl_results.get(slug=rule_group_slug)
            pgrgrs     = wsrgr.page_gl_results.all()
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                wsrgr      = wsr.ws_rs_results.get(slug=rule_group_slug)
                pgrgrs     = wsrgr.page_rs_results.all()
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                wsrgr      = wsr.ws_rc_results.get(slug=rule_group_slug)
                pgrgrs     = wsrgr.page_rc_results.all()
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for pgrgr in pgrgrs:
            pgrgr.title    = pgrgr.get_title()
            pgrgr.page_num = pgrgr.get_page_number()
            pgrgr.href     = reverse('group2_rule_group_results_audit_group2_website_page', args=[result_slug, rule_grouping, rule_group_slug, audit_group2_slug, website_slug, pgrgr.get_page_number()])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()


        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['rule_group_slug']   = rule_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['rule_group']    = rule_group

        context['audit_group2_result']  = ag2r
        context['website_result']       = wsrgr
        context['page_results']         = pgrgrs

        return context

class Group2RuleGroupResultsAuditGroup2WebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']

        ar   = AuditResult.objects.get(slug=result_slug)
        ag2r = AuditGroup2Result.objects.get(group_result__audit_result=ar, slug=audit_group2_slug)
        wsr  = WebsiteResult.objects.get(group2_result=ag2r, slug=website_slug)

        if rule_grouping == 'gl':
            wsrgr      = wsr.ws_gl_results.get(slug=rule_group_slug)
            pgrgr      = wsrgr.page_gl_results.get(page_result__page_number=page_num)
            pgrrrs     = pgrgr.page_rule_results.all()
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                wsrgr      = wsr.ws_rs_results.get(slug=rule_group_slug)
                pgrgr      = wsrgr.page_rs_results.get(page_result__page_number=page_num)
                pgrrrs     = pgrgr.page_rule_results.all()
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                wsrgr      = wsr.ws_rc_results.get(slug=rule_group_slug)
                pgrgr      = wsrgr.page_rc_results.get(page_result__page_number=page_num)
                pgrrrs     = pgrgr.page_rule_results.all()
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        for pgrrr in pgrrrs:
            pgrrr.title     = pgrrr.rule.summary_html
            pgrrr.href      = reverse('group2_rule_group_results_audit_group2_website_page_rule', args=[result_slug, rule_grouping, rule_group_slug, audit_group2_slug, website_slug, page_num, pgrrr.slug])

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num)
        self.result_nav.create_result_navigation()


        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['rule_group_slug']   = rule_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['rule_group']    = rule_group

        context['audit_group2_result']  = ag2r
        context['website_result']       = wsrgr
        context['page_result']          = pgrgr
        context['page_rule_results']    = pgrrrs

        return context

class Group2RuleGroupResultsAuditGroup2WebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'auditGroup2Results/group2_rule_group_results_audit_group2_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(Group2RuleGroupResultsAuditGroup2WebsitePageRuleView, self).get_context_data(**kwargs)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group_slug   = kwargs['rule_group_slug']
        audit_group2_slug = kwargs['audit_group2_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']
        rule_slug         = kwargs['rule_slug']

        ar   = AuditResult.objects.get(slug=result_slug)
        ag2r = AuditGroup2Result.objects.get(group_result__audit_result=ar, slug=audit_group2_slug)
        wsr  = WebsiteResult.objects.get(group2_result=ag2r, slug=website_slug)

        if rule_grouping == 'gl':
            wsrgr      = wsr.ws_gl_results.get(slug=rule_group_slug)
            pgrgr      = wsrgr.page_gl_results.get(page_result__page_number=page_num)
            pgrrr     = pgrgr.page_rule_results.get(slug=rule_slug)
            rule_group = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                wsrgr      = wsr.ws_rs_results.get(slug=rule_group_slug)
                pgrgr      = wsrgr.page_rs_results.get(page_result__page_number=page_num)
                pgrrr      = pgrgr.page_rule_results.get(slug=rule_slug)
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_grouping == 'rc'
                wsrgr      = wsr.ws_rc_results.get(slug=rule_group_slug)
                pgrgr      = wsrgr.page_rc_results.get(page_result__page_number=page_num)
                pgrrr      = pgrgr.page_rule_results.get(slug=rule_slug)
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)

        # Setup report navigation
        self.result_nav.set_audit_result(ar, 'group2', self.request.path)
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_audit_groups('', audit_group2_slug)
        self.result_nav.set_website_page(website_slug, page_num)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']        = ar.audit.slug
        context['result_slug']       = result_slug
        context['rule_grouping']     = rule_grouping
        context['rule_group_slug']   = rule_group_slug
        context['audit_group2_slug'] = audit_group2_slug
        context['website_slug']      = website_slug
        context['page_num']          = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['rule_group']    = rule_group

        context['audit_group2_result']  = ag2r
        context['website_result']       = wsrgr
        context['page_result']          = pgrgr
        context['page_rule_result']     = pgrrr
        context['rule']                 = pgrrr.rule

        return context
