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

from websiteResults.models import WebsiteResult
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

            r = WebsiteResult(slug=self.slug)

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
                    report = WebsiteResult.objects.filter(user=user).latest('last_viewed')
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

class ReportNotFoundView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_not_found.html'

    def get_context_data(self, **kwargs):
        context = super(RReportNotFoundView, self).get_context_data(**kwargs)

        context['report_slug']  = kwargs['report']
        
        return context            


class ReportRulesView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_rules.html'

    def get_context_data(self, **kwargs):
        context = super(ReportRulesView, self).get_context_data(**kwargs)

        view = kwargs['view']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()
        page = False

        if report.page_count == 1:
          page = report.get_first_page()
          if view == 'gl':
            groups = page.page_gl_results.all()
          elif view == 'rs':  
            groups = page.page_rs_results.all()
          else:  
            groups = page.page_rc_results.all()
            view = 'rc'
        else:
          if view == 'gl':
            groups = report.ws_gl_results.all()
          elif view == 'rs':  
            groups = report.ws_rs_results.all()
          else:  
            groups = report.ws_rc_results.all()
            view = 'rc'

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'rules', False)
        report_nav.set_current("Summary", reverse('report_rules', args=[report.slug, view]))

        report_nav.set_previous("","")    
        report_nav.set_next("","")    

        context['report_nav'] = report_nav

        context['page']     = page
        context['report']   = report
        context['view']     = view
        context['summary']  = report
        context['groups']   = groups
        
        return context            

        

class ReportRulesGroupView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_rules_group.html'

    def get_context_data(self, **kwargs):
        context = super(ReportRulesGroupView, self).get_context_data(**kwargs)

        view = kwargs['view']
        group_slug = kwargs['group']

        previous_group = False
        next_group     = False

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        if view == 'gl':
          group        = report.ws_gl_results.get(slug=group_slug)
          page_results = group.page_gl_results.all()
          groups       = Guideline.objects.all()
        elif view == 'rs':  
          group        = report.ws_rs_results.get(slug=group_slug)
          page_results = group.page_rs_results.all()
          groups       = RuleScope.objects.all()
        else:  
          group        = report.ws_rc_results.get(slug=group_slug)
            
          page_results = group.page_rc_results.all()
          groups       = RuleCategory.objects.all()
          view = 'rc'

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'rules', False)
        report_nav.set_current(group.get_title(), reverse('report_rules_group', args=[report.slug, view, group_slug]))

        [previous_group, next_group] = getPreviousNextGroup(groups, group_slug)
        if previous_group:
            report_nav.set_previous(previous_group.title + " Rules", reverse('report_rules_group', args=[report.slug, view, previous_group.slug]))
        else:
            report_nav.set_previous("","")    

        if next_group:
            report_nav.set_next(next_group.title + " Rules", reverse('report_rules_group', args=[report.slug, view, next_group.slug]))
        else:
            report_nav.set_next("","")    

        context['report_nav'] = report_nav

        context['report']       = report
        context['view']         = view
        context['summary']      = group
        context['group']        = group
        context['page_results'] = page_results
        
        return context            

class ReportRulesGroupRuleView(FAENavigationMixin, TemplateView):

    template_name = 'reports/report_rules_group_rule.html'

    def get_context_data(self, **kwargs):
        context = super(ReportRulesGroupRuleView, self).get_context_data(**kwargs)

        view = kwargs['view']
        group_slug = kwargs['group']
        rule_slug=kwargs['rule']

        previous_rule = False
        next_rule = False

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        if view == 'gl':
          group = report.ws_gl_results.get(slug=group_slug)
        elif view == 'rs':  
          group = report.ws_rs_results.get(slug=group_slug)
        else:  
          group = report.ws_rc_results.get(slug=group_slug)

          view = 'rc' 

        ws_rule_result = group.ws_rule_results.get(slug=rule_slug)

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'rules', False)
        report_nav.set_current(ws_rule_result.rule.nls_rule_id, reverse('report_rules_group_rule', args=[report.slug, view, group_slug, rule_slug]))

        [previous_rule, next_rule] = getPreviousNextRule(group.ws_rule_results.all().order_by('slug'), rule_slug)
        if previous_rule > 1:
            report_nav.set_previous(previous_rule.nls_rule_id, reverse('report_rules_group_rule', args=[report.slug, view, group_slug, previous_rule.slug]))
        else:
            report_nav.set_previous("","")    

        if next_rule:
            report_nav.set_next(next_rule.nls_rule_id, reverse('report_rules_group_rule', args=[report.slug, view, group_slug, next_rule.slug]))
        else:
            report_nav.set_next("","")    

        context['report_nav'] = report_nav

        context['report']           = report
        context['view']             = view
        context['group']            = group
        context['summary']          = ws_rule_result
        context['ws_rule_result']   = ws_rule_result
        
        return context            


class ReportRulesGroupRulePageView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_rules_group_rule_page.html'

    def get_context_data(self, **kwargs):
        context = super(ReportRulesGroupRulePageView, self).get_context_data(**kwargs)

        view  = kwargs['view']
        group_slug = kwargs['group']
        rule_slug  = kwargs['rule']
        page_slug  = kwargs['page']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        if   view == 'gl':
          group = report.ws_gl_results.get(slug=group_slug)
        elif view == 'rs':  
          group = report.ws_rs_results.get(slug=group_slug)
        else:  
          group = report.ws_rc_results.get(slug=group_slug)
          view_opt = 'rc'

        ws_rule_result   = group.ws_rule_results.get(slug=rule_slug)

        page_rule_result = ws_rule_result.page_rule_results.get(page_result__page_number=page_slug)

        page_number = page_rule_result.page_result.page_number

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'rules', page_slug)
        report_nav.set_current(ws_rule_result.rule.nls_rule_id + " - " + "Page " + page_slug, reverse('report_rules_group_rule_page', args=[report.slug, view, group_slug, rule_slug, page_slug]))
        if page_number > 1:
            report_nav.set_previous(ws_rule_result.rule.nls_rule_id + " - " + "Page " + str(page_number-1), reverse('report_rules_group_rule_page', args=[report.slug, view, group_slug, rule_slug, (page_number-1)]))
        else:
            report_nav.set_previous("","")    

        if page_number < report.page_count:
            report_nav.set_next(ws_rule_result.rule.nls_rule_id + " - " + "Page " + str(page_number+1), reverse('report_rules_group_rule_page', args=[report.slug, view, group_slug, rule_slug, (page_number+1)]))
        else:
            report_nav.set_next("","")    

        context['report_nav'] = report_nav

        context['report']   = report
        context['view']     = view
        context['group']    = group
        context['summary']           = page_rule_result
        context['page_rule_result']  = page_rule_result
        context['result_messages']   = formatted_result_messages(page_rule_result.result_message)       
        return context      

class ReportRulesGroupRulePageElementResultsJSON(TemplateView):
    template_name = 'reports/report_rules_group_rule_page.html'

    def get_context_data(self, **kwargs):
        context = super(ReportRulesGroupRulePageView, self).get_context_data(**kwargs)

        view = kwargs['view']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        if view == 'gl':
          group = report.ws_gl_results.get(slug=kwargs['group'])
        elif view == 'rs':  
          group = report.ws_rs_results.get(slug=kwargs['group'])
        else:  
          group = report.ws_rc_results.get(slug=kwargs['group'])
          view_opt = 'rc'

        ws_rule_result   = group.ws_rule_results.get(slug=kwargs['rule'])
        page_rule_result = ws_rule_result.page_rule_results.get(page_result__page_number=kwargs['page'])

        context['result_messages'] = formatted_result_messages(page_rule_result.result_message)

        context['report']   = report
        context['view']     = view
        context['group']    = group
        context['summary']           = page_rule_result
        context['page_rule_result']  = page_rule_result
        return context    

class ReportPagesView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_pages.html'

    def get_context_data(self, **kwargs):
        context = super(ReportPagesView, self).get_context_data(**kwargs)

        view = kwargs['view']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        page = False
        groups = []

        if report.page_count == 1:
          page = report.get_first_page()
          if view == 'gl':
            groups = page.page_gl_results.all()
          elif view == 'rs':  
            groups = page.page_rs_results.all()
          else:  
            groups = page.page_rc_results.all()
            view = 'rc'

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'pages', False)
        report_nav.set_current("All Pages", reverse('report_pages', args=[report.slug, view]))

        report_nav.set_previous("","")
        report_nav.set_next("","")

        context['report_nav'] = report_nav


        context['page']     = page
        context['report']   = report
        context['view']     = view
        context['summary']  = report.get_pages_summary()
        context['groups']   = groups
        
        return context            

class ReportPagesGroupView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_pages_group.html'

    def get_context_data(self, **kwargs):
        context = super(ReportPagesGroupView, self).get_context_data(**kwargs)

        view  = kwargs['view']
        group_slug = kwargs['group']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        page = False
        groups = []

        if report.page_count == 1:
          page = report.get_first_page()
          if view == 'gl':
            groups = page.page_gl_results.all()
          elif view == 'rs':  
            groups = page.page_rs_results.all()
          else:  
            groups = page.page_rc_results.all()
            view = 'rc'
        else:
          if view == 'gl':
            page_results = PageGuidelineResult.objects.filter(page_result__ws_report=report, guideline__slug=group_slug)
            group_info   = Guideline.objects.get(slug=group_slug)
            groups       = Guideline.objects.all()

          elif view == 'rs':  
            page_results = PageRuleScopeResult.objects.filter(page_result__ws_report=report, rule_scope__slug=group_slug)
            group_info   = RuleScope.objects.get(slug=group_slug)
            groups       = RuleScope.objects.all()

          else:  
            page_results = PageRuleCategoryResult.objects.filter(page_result__ws_report=report, rule_category__slug=group_slug)
            group_info   = RuleCategory.objects.get(slug=group_slug)
            groups       = RuleCategory.objects.all()
            view = 'rc'
            

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'pages', False)
        report_nav.set_current(group_info.title + " Rules", reverse('report_pages_group', args=[report.slug, view, group_slug]))

        [previous_group, next_group] = getPreviousNextGroup(groups, group_slug)
        if previous_group:
            report_nav.set_previous(previous_group.title + " Rules", reverse('report_pages_group', args=[report.slug, view, previous_group.slug]))
        else:
            report_nav.set_previous("","")    

        if next_group:
            report_nav.set_next(next_group.title + " Rules", reverse('report_pages_group', args=[report.slug, view, next_group.slug]))
        else:
            report_nav.set_next("","")    

        context['report_nav'] = report_nav


        context['page']     = page
        context['report']   = report
        context['view']     = view
        context['summary']  = report.get_pages_summary(view, group_slug)
        context['page_results']   = page_results
        context['group']    = group_info
        
        return context     
        
class ReportPageView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_page.html'

    def get_context_data(self, **kwargs):
        context = super(ReportPageView, self).get_context_data(**kwargs)

        view      = kwargs['view']
        page_slug = kwargs['page']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        page   = report.page_all_results.get(page_number=page_slug)
        page_number = page.page_number

        if view == 'gl':
          groups = page.page_gl_results.all()
        elif view == 'rs':  
          groups = page.page_rs_results.all()
        else:  
          groups = page.page_rc_results.all()
          view_opt = 'rc'

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'page', page.page_number)
        report_nav.set_current("Page " + page_slug, reverse('report_page', args=[report.slug, view, page_slug]))

        if page_number > 1:
            report_nav.set_previous("Page " + str(page_number-1), reverse('report_page', args=[report.slug, view, (page_number-1)]))
        else:
            report_nav.set_previous("","")    

        if page_number < report.page_count:
            report_nav.set_next("Page " + str(page_number+1), reverse('report_page', args=[report.slug, view, (page_number+1)]))
        else:
            report_nav.set_next("","")    

        context['report_nav'] = report_nav

        context['report']        = report
        context['view']          = view
        context['summary']       = page
        context['groups']        = groups
        context['page']          = page
        
        return context            


class ReportPageGroupView(FAENavigationMixin, TemplateView):
    template_name = 'reports/report_page_group.html'

    def get_context_data(self, **kwargs):
        context = super(ReportPageGroupView, self).get_context_data(**kwargs)

        view = kwargs['view']
        page_slug = kwargs['page']
        group_slug = kwargs['group']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()

        page   = report.page_all_results.get(page_number=page_slug)
        if view == 'gl':
          group_results = page.page_gl_results.get(slug=group_slug)
          group_info    = Guideline.objects.get(slug=group_slug)
          groups        = Guideline.objects.all()
        elif view == 'rs':  
          group_results = page.page_rs_results.get(slug=group_slug)
          group_info    = RuleScope.objects.get(slug=group_slug)
          groups        = RuleScope.objects.all()
        else:  
          group_results = page.page_rc_results.get(slug=group_slug)
          group_info    = RuleCategory.objects.get(slug=group_slug)
          groups        = RuleCategory.objects.all()
          view_opt = 'rc'

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'page', page.page_number)
        report_nav.set_current(group_info.title + " Rules", reverse('report_page_group', args=[report.slug, view, group_slug, page_slug]))

        [previous_group, next_group] = getPreviousNextGroup(groups, group_slug)
        if previous_group:
            report_nav.set_previous(previous_group.title + " Rules", reverse('report_page_group', args=[report.slug, view, previous_group.slug, page_slug]))
        else:
            report_nav.set_previous("","")    

        if next_group:
            report_nav.set_next(next_group.title + " Rules", reverse('report_page_group', args=[report.slug, view, next_group.slug, page_slug]))
        else:
            report_nav.set_next("","")    

        context['report_nav'] = report_nav

        context['report']        = report
        context['view']          = view
        context['summary']       = group_results
        context['group'] = group_results     
        context['page']          = page
        
        return context           

class ReportPageGroupRuleView(FAENavigationMixin, TemplateView):

    template_name = 'reports/report_page_group_rule.html'

    def get_context_data(self, **kwargs):
        context = super(ReportPageGroupRuleView, self).get_context_data(**kwargs)

        view = kwargs['view']
        page_slug  = kwargs['page']
        group_slug = kwargs['group']
        rule_slug  = kwargs['rule']

        report = WebsiteResult.objects.get(slug=kwargs['report'])
        report.update_last_viewed()
        
        page   = report.page_all_results.get(page_number=page_slug)
        if view == 'gl':
          group = page.page_gl_results.get(slug=group_slug)

        elif view == 'rs':  
          group = page.page_rs_results.get(slug=group_slug)
        else:  
          group = page.page_rc_results.get(slug=group_slug)
          view_opt = 'rc'

        page_rule_result = group.page_rule_results.get(slug=rule_slug)

        report_nav = FAENavigtionObject(self.request.session)
        report_nav.set_fae_navigation(report.slug, report.page_count, view, 'page', page.page_number)
        report_nav.set_current("Page " + page_slug + " - " + page_rule_result.rule.nls_rule_id , reverse('report_page_group_rule', args=[report.slug, view, group_slug, page_slug, rule_slug]))

        [previous_rule, next_rule] = getPreviousNextRule(group.page_rule_results.all().order_by('slug'), rule_slug)
        if previous_rule > 1:
            report_nav.set_previous("Page " + page_slug + " - " + previous_rule.nls_rule_id, reverse('report_page_group_rule', args=[report.slug, view, group_slug, page_slug, previous_rule.slug]))
        else:
            report_nav.set_previous("","")

        if next_rule:
            report_nav.set_next("Page " + page_slug + " - " + next_rule.nls_rule_id, reverse('report_page_group_rule', args=[report.slug, view, group_slug, page_slug, next_rule.slug]))
        else:
            report_nav.set_next("","")

        context['report_nav'] = report_nav

        context['result_messages'] = formatted_result_messages(page_rule_result.result_message)

        context['report']        = report
        context['view']          = view
        context['summary']       = page
        context['group']         = group
        context['page']          = page
        context['page_rule_result'] = page_rule_result

        return context             


class URLInformationView(FAENavigationMixin, TemplateView):
    template_name = 'reports/url_information.html'

    def get_context_data(self, **kwargs):
        context = super(URLInformationView, self).get_context_data(**kwargs)

        report = WebsiteResult.objects.get(slug=kwargs['report'])

        context['report'] = report
        
        return context            
        