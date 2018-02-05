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



# ==============================================================
#
# Utiltiy functions
#
# ==============================================================

def check_url(url):

   url = url.strip()

   url = ''.join(c for c in url if ord(c)<128)

   if url.find('http://') == 0 or url.find('https://') == 0:
     return url

   return 'http://' + url


def formatted_result_messages(result_message):

    class FormattedResultMessage:

        def __init__(self):
            self.severity = "no actions"
            self.message = ""
            self.style ="none"

    frms = []

    if len(result_message) and result_message.find(':'):
        rms = result_message.split(';')

        for rm in rms:
            frm = FormattedResultMessage()

            parts = rm.split(':')

            if len(parts) > 1:
              frm.message  = parts[1]

            if rm.find('P:') >= 0:
                frm.severity = 'Pass'
                frm.style = 'pass'
            elif rm.find('V:') >= 0:
                frm.severity = 'Violation'
                frm.style = 'violation'
            elif rm.find('W:') >= 0:
                frm.severity = 'Warning'
                frm.style = 'warning'
            elif rm.find('MC:') >= 0:
                frm.severity = 'Manual Check'
                frm.style = 'manual_check'
            elif rm.find("H:") >= 0:
                frm.severity = 'Hidden'
                frm.style = 'fae-hidden'

            frms.append(frm)
    else:
        frm = FormattedResultMessage()
        frms.append(frm)
    return frms

def getPreviousNextRule(rule_results, current_slug):

    p = False
    n = False
    for rr in rule_results:
        if rr.rule.slug == current_slug:
            break
        p = rr.rule

    flag = False
    for rr in rule_results:
        if flag:
            n = rr.rule
            break

        if rr.rule.slug == current_slug:
            flag = True

    return [p,n]

def getPreviousNextGroup(groups, current_slug):

    p = False
    n = False
    for g in groups:
#            print("[getPreviousNextRule]:" + str(prr.rule.slug) + " " + rule_slug)
        if g.slug == current_slug:
            break
        p = g

    flag = False
    for g in groups:
        if flag:
            n = g
            break

        if g.slug == current_slug:
            flag = True

    return [p,n]

# ==============================================================
#
# FAE 2.0 Navigation Mixin
#
# ==============================================================

class FilterViewItem:

    def __init__(self, label, url):
        self.label = label
        self.url   = url


class FAENavigtionObject:

    slug = False
    page_count = 0
    view = 'rc'
    report_type = 'rules'
    page = 0

    current_label = ""
    current_url   = ""

    previous_label = ""
    previous_url   = ""

    next_label = ""
    next_url   = ""

    def __init__(self, session, user=False):

        self.session = session

        try:
            self.slug = session['report_slug']

            r = WebsiteReport(slug=self.slug)

            try:
                self.view = session['report_view']
            except:
                self.view = 'rc'

            try:
                self.page  = session['report_page']
            except:
                self.page  = 1

            try:
                self.report_type = session['report_type']
            except:
                self.report_type = 'rules'

            try:
                self.page_count = session['report_page_count']
            except:
                self.page_count = 1

            try:
                self.current_label  = session['current_label']
                self.current_url    = session['current_url']
            except:
                self.current_label  = False
                self.current_url    = False

            try:
                self.next_label     = session['next_label']
                self.next_url       = session['next_url']
            except:
                self.next_label     = False
                self.next_url       = False

            try:
                self.previous_label = session['previous_label']
                self.previous_url   = session['previous_url']
            except:
                self.previous_label = False
                self.previous_url   = False

        except:
            self.slug = False
            self.view = 'rc'
            self.page  = 1
            self.report_type = 'rules'
            self.page_count = 1

            self.previous_label = False
            self.previous_url   = False
            self.current_label  = False
            self.current_url    = False
            self.next_label     = False
            self.next_url       = False

        if self.slug:
            self.update_filters()
        else:
            if user and len(user.username) and user.username != 'anonymous':
                try:
                    report = WebsiteReport.objects.filter(user=user).latest('last_viewed')
                except:
                    report = False

                if report:
                    self.set_fae_navigation(report.slug, report.page_count, report.last_view, report.last_report_type, report.last_page)


    def update_filters(self):

        self.filters = []

        if self.view == 'rs':
            self.add_rule_scope_filter()
        elif self.view == 'gl':
            self.add_guideline_filter()
        else:
            self.add_rule_category_filter()

    def set_fae_navigation(self, slug, page_count, view, type, page):

        if slug:
          self.slug                    = slug
          self.session['report_slug']       = slug

          self.page_count              = page_count
          self.session['report_page_count'] = page_count

        if view:
          self.view = view
          self.session['report_view'] = view

        if type:
          self.report_type = type
          self.session['report_type'] = type

        if page:
          self.page = page
          self.session['report_page'] = page

        self.update_filters()


    def set_current(self, label, url):
        self.current_label            = label
        self.session['current_label'] = label
        self.current_url              = url
        self.session['current_url']   = url


    def set_next(self, label, url):
        self.next_label            = label
        self.session['next_label'] = label
        self.next_url              = url
        self.session['next_url']   = url


    def set_previous(self, label, url):
        self.previous_label            = label
        self.session['previous_label'] = label
        self.previous_url              = url
        self.session['previous_url']   = url


    def add_filter_item(self, group, label):

        if self.report_type == 'page':
            if group:
                url = reverse('report_page_group', args=[self.slug, self.view, group, self.page])
            else:
                url = reverse('report_page', args=[self.slug, self.view, self.page])

        elif self.report_type == 'pages':
            if group:
                url = reverse('report_pages_group', args=[self.slug, self.view, group])
            else:
                url = reverse('report_pages', args=[self.slug, self.view])

        else:
            self.report_type = 'rules'
            if group:
                url = reverse('report_rules_group', args=[self.slug, self.view, group])
            else:
                url = reverse('report_rules', args=[self.slug, self.view])

        fi = FilterViewItem(label, url)

        self.filters.append(fi)

    def add_rule_category_filter(self):
        rcs = RuleCategory.objects.all()
        self.add_filter_item(False, "All Groups")
        for rc in rcs:
            self.add_filter_item(rc.slug, rc.title)

    def add_guideline_filter(self):
        gls = Guideline.objects.all()
        self.add_filter_item(False, "All Groups")
        for gl in gls:
            self.add_filter_item(gl.slug, gl.title)

    def add_rule_scope_filter(self):
        rss = RuleScope.objects.all()
        self.add_filter_item(False, "All Groups")
        for rs in rss:
            self.add_filter_item(rs.slug, rs.title)

class FAENavigationMixin(object):

    def get_context_data(self, **kwargs):

        context = super(FAENavigationMixin, self).get_context_data(**kwargs)

        context['report_nav'] = FAENavigtionObject(self.request.session, self.request.user)

        return context




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

class ReportNotFoundView(TemplateView):
    template_name = 'websiteResults/report_not_found.html'

    def get_context_data(self, **kwargs):
        context = super(RReportNotFoundView, self).get_context_data(**kwargs)

        context['report_slug']  = kwargs['report']

        return context


class WebsiteResultsWebsiteInfoView(TemplateView):
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

class WebsiteResultsView(TemplateView):
    template_name = 'websiteResults/website_results.html'

    def get_context_data(self, **kwargs):
        context = super(WebsiteResultsView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_groups       = Guideline.objects.all()
            rule_grouping_label  = "Guideline"
        else:
            if rule_grouping == 'rs':
                rule_groups      = RuleScope.objects.all()
                rule_grouping_label = "Rule Scope"
            else:
                rule_groups      = RuleCategory.objects.all()
                rule_grouping_label = "Rule Category"
                rule_grouping    = 'rc'

        wsrs = ar.ws_results.all()

        for wsr in wsrs:
            wsr.href         = reverse('website_results_website', args=[result_slug, rule_grouping, wsr.slug])
            if ar.audit.groups:
                wsr.group_title  = wsr.group_result.group_item.title
                if ar.audit.group2s:
                    wsr.group2_title = wsr.group2_result.group2_item.title

        # slugs used for urls
        context['audit_slug']     = ar.audit.slug
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['website_results']     = wsrs

        return context

class WebsiteResultsWebsiteView(TemplateView):
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

        if rule_grouping == 'gl':
            rule_groups       = Guideline.objects.all()
            rule_grouping_label  = "Guideline"
        else:
            if rule_grouping == 'rs':
                rule_groups      = RuleScope.objects.all()
                rule_grouping_label = "Rule Scope"
            else:
                rule_groups      = RuleCategory.objects.all()
                rule_grouping_label = "Rule Category"
                rule_grouping    = 'rc'


        for pr in page_results:
            pr.page_num  = pr.page_number
            pr.title     = pr.get_title()
            pr.href      = reverse('website_results_website_page', args=[result_slug, rule_grouping, website_slug, pr.page_number])

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['website_slug']    = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['website_result']      = wsr
        context['page_results']        = page_results

        return context

class WebsiteResultsWebsitePageView(TemplateView):
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

        if rule_grouping == 'gl':
            rule_groups       = Guideline.objects.all()
            rule_grouping_label  = "Guideline"
        else:
            if rule_grouping == 'rs':
                rule_groups      = RuleScope.objects.all()
                rule_grouping_label = "Rule Scope"
            else:
                rule_groups      = RuleCategory.objects.all()
                rule_grouping_label = "Rule Category"
                rule_grouping    = 'rc'


        for prr in prrs:
            prr.title     = prr.rule.summary_html
            prr.href      = reverse('website_results_website_page_rule', args=[result_slug, rule_grouping, website_slug, page_num, prr.slug])

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

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_results']   = prrs

        return context

class WebsiteResultsWebsitePageRuleView(TemplateView):
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

        if rule_grouping == 'gl':
            rule_groups       = Guideline.objects.all()
            rule_grouping_label  = "Guideline"
        else:
            if rule_grouping == 'rs':
                rule_groups      = RuleScope.objects.all()
                rule_grouping_label = "Rule Scope"
            else:
                rule_groups      = RuleCategory.objects.all()
                rule_grouping_label = "Rule Category"
                rule_grouping    = 'rc'

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

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['website_result']      = wsr
        context['page_result']         = pr
        context['page_rule_result']    = prr
        context['rule']                = r

        return context

class WebsiteRuleGroupResultsView(TemplateView):
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
            rule_groups       = Guideline.objects.all()
            wsrgrs            = WebsiteGuidelineResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
            rule_grouping_label  = "Guideline"
            rule_group        = Guideline.objects.get(slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_groups      = RuleScope.objects.all()
                wsrgrs           = WebsiteRuleScopeResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_grouping_label = "Rule Scope"
                rule_group        = RuleScope.objects.get(slug=rule_group_slug)
            else:
                rule_groups      = RuleCategory.objects.all()
                wsrgrs           = WebsiteRuleCategoryResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_grouping_label = "Rule Category"
                rule_group        = RuleCategory.objects.get(slug=rule_group_slug)
                rule_grouping    = 'rc'


        for wsrgr in wsrgrs:
            wsrgr.title = wsrgr.ws_report.get_title()
            wsrgr.href         = reverse('website_rule_group_results_website', args=[result_slug, rule_grouping, rule_group_slug, wsrgr.ws_report.slug])
            if ar.audit.groups:
                wsrgr.group_title  = wsrgr.ws_report.group_result.group_item.title
                if ar.audit.group2s:
                    wsrgr.group2_title = wsrgr.ws_report.group2_result.group2_item.title

        # slugs used for urls
        context['audit_slug']      = ar.audit.slug
        context['result_slug']     = result_slug
        context['rule_grouping']   = rule_grouping
        context['rule_group_slug'] = rule_group_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['rule_group_slug']     = rule_group_slug
        context['rule_group']          = rule_group
        context['website_results']     = wsrgrs

        return context

class WebsiteRuleGroupResultsWebsiteView(TemplateView):
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
            rule_groups       = Guideline.objects.all()
            wsrgrs            = WebsiteGuidelineResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
            rule_grouping_label  = "Guideline"
            rule_group        = Guideline.objects.get(slug=rule_group_slug)
            page_results      = PageGuidelineResult.objects.filter(page_result__ws_report=wsr, slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_groups      = RuleScope.objects.all()
                wsrgrs           = WebsiteRuleScopeResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_grouping_label = "Rule Scope"
                rule_group        = RuleScope.objects.get(slug=rule_group_slug)
                page_results      = PageRuleScopeResult.objects.filter(page_result__ws_report=wsr, slug=rule_group_slug)
            else:
                rule_groups      = RuleCategory.objects.all()
                wsrgrs           = WebsiteRuleCategoryResult.objects.filter(ws_report__audit_result=ar, slug=rule_group_slug)
                rule_grouping_label = "Rule Category"
                rule_group        = RuleCategory.objects.get(slug=rule_group_slug)
                page_results      = PageRuleCategoryResult.objects.filter(page_result__ws_report=wsr, slug=rule_group_slug)
                rule_grouping    = 'rc'


        for pr in page_results:
            pr.page_num  = pr.page_result.page_number
            pr.title     = pr.page_result.get_title()
            pr.href      = reverse('website_rule_group_results_website_page', args=[result_slug, rule_grouping, rule_group_slug, website_slug, pr.page_result.page_number])

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

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['rule_group']          = rule_group
        context['website_result']      = wsr
        context['page_results']        = page_results

        return context

class WebsiteRuleGroupResultsWebsitePageView(TemplateView):
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
            rule_groups          = Guideline.objects.all()
            rule_grouping_label  = "Guideline"
            rule_group           = Guideline.objects.get(slug=rule_group_slug)
            page_result          = PageGuidelineResult.objects.get(page_result__ws_report=wsr, page_result__page_number=page_num, slug=rule_group_slug)
        else:
            if rule_grouping == 'rs':
                rule_groups         = RuleScope.objects.all()
                rule_grouping_label = "Rule Scope"
                rule_group          = RuleScope.objects.get(slug=rule_group_slug)
                page_result         = PageRuleScopeResult.objects.get(page_result__ws_report=wsr, page_result__page_number=page_num, slug=rule_group_slug)
            else:
                rule_groups         = RuleCategory.objects.all()
                rule_grouping_label = "Rule Category"
                rule_group          = RuleCategory.objects.get(slug=rule_group_slug)
                page_result         = PageRuleCategoryResult.objects.get(page_result__ws_report=wsr, page_result__page_number=page_num, slug=rule_group_slug)
                rule_grouping       = 'rc'


        prrs = page_result.page_rule_results.all()

        for prr in prrs:
            prr.title = prr.rule.summary_html
            prr.href = reverse('website_rule_group_results_website_page_rule', args=[result_slug, rule_grouping, rule_group_slug, website_slug, page_num, prr.slug])

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

        context['rule_grouping_label'] = rule_grouping_label
        context['rule_groups']         = rule_groups
        context['rule_group']          = rule_group
        context['website_result']      = wsr
        context['page_result']         = page_result
        context['page_rule_results']   = prrs

        return context

class WebsiteRuleGroupResultsWebsitePageRuleView(TemplateView):
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
