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

file: websiteResults/views.py

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
from auditGroup2Results.models import AuditGroup2Result

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
from audits.uid import generate

from audits.resultNavigationMixin import ResultNavigationMixin

# ==============================================================
#
# Website Report Views
#
# ==============================================================


class ReportJSON(TemplateView):

    def render_to_response(self, context, **response_kwargs):

        return  JsonResponse(context['report'].to_json_results(), safe=False, **response_kwargs)

    def get_context_data(self, **kwargs):
        context = super(ReportJSON, self).get_context_data(**kwargs)

        report = WebsiteResult.objects.get(slug=kwargs['report'])

        context['report'] = report

        return context

class ReportNotFoundView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/report_not_found.html'

    def get_context_data(self, **kwargs):
        context = super(RReportNotFoundView, self).get_context_data(**kwargs)

        context['report_slug']  = kwargs['report']

        return context


class WebsiteResultsWebsiteInfoView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/url_information.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteResultsWebsiteInfoView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']
        website_slug   = kwargs['website_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        website_result = WebsiteResult.objects.get(audit_result=ar, slug=kwargs['website_slug'])

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile
        context['website_slug']  = website_slug

        context['wesbsite_result'] = website_result

        return context

class WebsiteResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_results.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        wsrs = ar.ws_results.all()

        for wsr in wsrs:
            wsr.href         = reverse('website_results_website', args=[result_slug, rule_grouping, wsr.slug])
            if wsr.group_result:
                wsr.group_title  = wsr.group_result.group_item.title
                if wsr.group2_result:
                    wsr.group2_title = wsr.group2_result.group2_item.title

        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['website_results']     = wsrs

        return context

class WebsiteResultsWebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_results_website.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteResultsWebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        website_slug    = kwargs['website_slug']

        ar  = AuditResult.objects.get(slug=result_slug)
        wsr = ar.ws_results.get(slug=website_slug)

        page_results = wsr.page_all_results.all()

        for pr in page_results:
            pr.page_num  = pr.page_number
            pr.title     = pr.get_title()
            pr.href      = reverse('website_results_website_page', args=[result_slug, rule_grouping, website_slug, pr.page_number])

        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['website_slug']    = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['website_result']      = wsr
        context['page_results']        = page_results

        return context

class WebsiteResultsWebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_results_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteResultsWebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        website_slug    = kwargs['website_slug']
        page_num        = kwargs['page_num']

        ar  = AuditResult.objects.get(slug=result_slug)
        wsr = ar.ws_results.get(slug=website_slug)

        pr   = wsr.page_all_results.get(page_number=page_num)
        prrs = pr.page_rule_results.all()

        for prr in prrs:
            prr.title     = prr.rule.summary_html
            prr.href      = reverse('website_results_website_page_rule', args=[result_slug, rule_grouping, website_slug, page_num, prr.slug])

        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['website_slug']    = website_slug
        context['page_num']        = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_results']   = prrs

        return context

class WebsiteResultsWebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_results_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteResultsWebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        website_slug    = kwargs['website_slug']
        page_num        = kwargs['page_num']
        rule_slug       = kwargs['rule_slug']

        ar  = AuditResult.objects.get(slug=result_slug)
        wsr = ar.ws_results.get(slug=website_slug)
        pr  = wsr.page_all_results.get(page_number=page_num)
        prr = pr.page_rule_results.get(slug=rule_slug)
        r   = prr.rule

        # Se
        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.set_rule(rule_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping
        context['website_slug']   = website_slug
        context['page_num']       = page_num
        context['rule_slug']      = rule_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context

class WebsiteRuleGroupResultsView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_rule_group_results.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteRuleGroupResultsView, self).get_context_data(**kwargs)


        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        rule_group_slug = kwargs['rule_group_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            wsrgrs            = WebsiteGuidelineResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
            rule_group        = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                wsrgrs           = WebsiteRuleScopeResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_group        = RuleScope.objects.get(slug=rule_group_slug)
            else:
                wsrgrs           = WebsiteRuleCategoryResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_group        = RuleCategory.objects.get(slug=rule_group_slug)


        for wsrgr in wsrgrs:
            wsrgr.title = wsrgr.ws_report.get_title()
            wsrgr.href  = reverse('website_rule_group_results_website', args=[result_slug, rule_grouping, rule_group_slug, wsrgr.ws_report.slug])
            if wsrgr.ws_report.group_result:
                wsrgr.group_title  = wsrgr.ws_report.group_result.group_item.title
                if wsrgr.ws_report.group2_result:
                    wsrgr.group2_title = wsrgr.ws_report.group2_result.group2_item.title

        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
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

        context['rule_group']          = rule_group
        context['website_results']     = wsrgrs

        return context

class WebsiteRuleGroupResultsWebsiteView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_rule_group_results_website.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteRuleGroupResultsWebsiteView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        rule_group_slug = kwargs['rule_group_slug']
        website_slug    = kwargs['website_slug']

        ar  = AuditResult.objects.get(slug=result_slug)
        wsr = ar.ws_results.get(slug=website_slug)

        if rule_grouping == 'gl':
            rule_group        = Guideline.objects.get(slug=rule_group_slug)
            page_results      = PageGuidelineResult.objects.filter(page_result__ws_report=wsr, slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_group        = RuleScope.objects.get(slug=rule_group_slug)
                page_results      = PageRuleScopeResult.objects.filter(page_result__ws_report=wsr, slug=rule_group_slug)
            else:
                rule_group        = RuleCategory.objects.get(slug=rule_group_slug)
                page_results      = PageRuleCategoryResult.objects.filter(page_result__ws_report=wsr, slug=rule_group_slug)


        for pr in page_results:
            pr.page_num  = pr.page_result.page_number
            pr.title     = pr.page_result.get_title()
            pr.href      = reverse('website_rule_group_results_website_page', args=[result_slug, rule_grouping, rule_group_slug, website_slug, pr.page_result.page_number])

        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_website_page(website_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug
        context['website_slug']    = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']          = rule_group
        context['website_result']      = wsr
        context['page_results']        = page_results

        return context

class WebsiteRuleGroupResultsWebsitePageView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_rule_group_results_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteRuleGroupResultsWebsitePageView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        rule_group_slug = kwargs['rule_group_slug']
        website_slug    = kwargs['website_slug']
        page_num        = kwargs['page_num']

        ar  = AuditResult.objects.get(slug=result_slug)
        wsr = ar.ws_results.get(slug=website_slug)

        if rule_grouping == 'gl':
            rule_group = Guideline.objects.get(slug=rule_group_slug)
            pr         = PageGuidelineResult.objects.get(page_result__ws_report=wsr, page_result__page_number=page_num, slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_group = RuleScope.objects.get(slug=rule_group_slug)
                pr         = PageRuleScopeResult.objects.get(page_result__ws_report=wsr, page_result__page_number=page_num, slug=rule_group_slug)
            else:
                rule_group = RuleCategory.objects.get(slug=rule_group_slug)
                pr         = PageRuleCategoryResult.objects.get(page_result__ws_report=wsr, page_result__page_number=page_num, slug=rule_group_slug)


        prrs = pr.page_rule_results.all()

        for prr in prrs:
            prr.title = prr.rule.summary_html
            prr.href = reverse('website_rule_group_results_website_page_rule', args=[result_slug, rule_grouping, rule_group_slug, website_slug, page_num, prr.slug])

        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug
        context['website_slug']    = website_slug
        context['page_num']        = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group']          = rule_group
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_results']   = prrs

        return context

class WebsiteRuleGroupResultsWebsitePageRuleView(ResultNavigationMixin, TemplateView):
    template_name = 'websiteResults/website_rule_group_results_website_page_rule.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteRuleGroupResultsWebsitePageRuleView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug     = kwargs['result_slug']
        rule_grouping   = kwargs['rule_grouping']
        rule_group_slug = kwargs['rule_group_slug']
        website_slug    = kwargs['website_slug']
        page_num        = kwargs['page_num']
        rule_slug       = kwargs['rule_slug']


        ar  = AuditResult.objects.get(slug=result_slug)
        wsr = ar.ws_results.get(slug=website_slug)
        pr  = wsr.page_all_results.get(page_number=page_num)
        prr = pr.page_rule_results.get(slug=rule_slug)
        r   = prr.rule

        if rule_grouping == 'gl':
            rule_groups          = Guideline.objects.all()
            rule_grouping_label  = "Guideline"
            rule_group           = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_groups         = RuleScope.objects.all()
                rule_grouping_label = "Rule Scope"
                rule_group          = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_groups         = RuleCategory.objects.all()
                rule_grouping_label = "Rule Category"
                rule_group          = RuleCategory.objects.get(slug=rule_group_slug)
                rule_grouping       = 'rc'


        self.result_nav.set_audit_result(ar.slug, result_slug, 'website')
        self.result_nav.set_rule_grouping(rule_grouping, rule_group_slug)
        self.result_nav.set_website_page(website_slug, page_num, wsr.page_count)
        self.result_nav.set_rule(rule_slug)
        self.result_nav.create_result_navigation()

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug
        context['website_slug']    = website_slug
        context['page_num']        = page_num
        context['rule_slug']       = rule_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['rule_group']          = rule_group
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context
