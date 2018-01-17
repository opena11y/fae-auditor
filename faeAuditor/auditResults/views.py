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

file: audits/views.py

Author: Jon Gunderson

"""

from __future__ import absolute_import

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import JsonResponse
from django.shortcuts import redirect

from django.contrib import messages

from itertools import chain

from django.core.urlresolvers import reverse_lazy, reverse
from django.contrib.auth.mixins import LoginRequiredMixin

from django.views.generic import TemplateView
from django.views.generic import CreateView
from django.views.generic import FormView
from django.views.generic import RedirectView

from django.contrib.auth.models import User

from rules.models  import Rule
from audits.models import Audit
from .models       import AuditResult

from userProfiles.models import UserProfile


from django.utils.http import is_safe_url
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, RedirectView


class AuditResultView(TemplateView):
    template_name = 'auditResults/audit_result.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultView, self).get_context_data(**kwargs)

        user        = self.request.user
        result_slug = kwargs['result_slug']
        grouping    = kwargs['grouping']

        user_profile = UserProfile.objects.get(user=user)

        ar = AuditResult.objects.get(slug=result_slug)

        if grouping == 'gl':
            group_results = ar.results_by_guideline()
        else:
            if grouping == 'rs':
                group_results = ar.results_by_rule_scope()
            else:
                group_results = ar.results_by_rule_category()
                grouping = 'rc'

        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['grouping']      = grouping

        context['group_results'] = group_results
        context['user_profile']  = user_profile

        return context

class AuditResultGroupView(TemplateView):
    template_name = 'auditResults/audit_result_group.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultGroupView, self).get_context_data(**kwargs)

        user        = self.request.user
        result_slug = kwargs['result_slug']
        grouping    = kwargs['grouping']
        group       = kwargs['group']

        user_profile = UserProfile.objects.get(user=user)

        ar = AuditResult.objects.get(slug=result_slug)

        if grouping == 'gl':
            group_results      = ar.results_by_guideline()
            group_result       = ar.audit_gl_results.get(slug=group)
        else:
            if grouping == 'rs':
                group_results      = ar.results_by_scope()
                group_result       = ar.audit_rs_results.get(slug=group)
            else:
                group_results      = ar.results_by_rule_category()
                group_result       = ar.audit_rc_results.get(slug=group)
                grouping = 'rc'

        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['grouping']      = grouping
        context['group']         = group

        context['group_results']      = group_results
        context['group_result']       = group_result
        context['group_rule_results'] = group_result.audit_rule_results.all()
        context['user_profile']       = user_profile

        return context

class AuditResultGroupRuleView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultGroupRuleView, self).get_context_data(**kwargs)

        user        = self.request.user
        result_slug = kwargs['result_slug']
        grouping    = kwargs['grouping']
        group       = kwargs['group']
        rule        = kwargs['rule']

        user_profile = UserProfile.objects.get(user=user)

        ar = AuditResult.objects.get(slug=result_slug)

        if grouping == 'gl':
            group_results      = ar.results_by_guideline()
            group_result       = ar.audit_gl_results.get(slug=group)
        else:
            if grouping == 'rs':
                group_results      = ar.results_by_scope()
                group_result       = ar.audit_rs_results.get(slug=group)
            else:
                group_results      = ar.results_by_rule_category()
                group_result       = ar.audit_rc_results.get(slug=group)
                grouping = 'rc'

        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['grouping']      = grouping
        context['group']         = group
        context['rule']          = Rule.objects.get(slug=rule)

        context['group_results']           = group_results
        context['group_result']            = group_result
        context['group_rule_results']      = ar.group_rule_results(rule)
        context['all_group2_rule_results'] = ar.all_group2_rule_results(rule)
        context['website_rule_results']    = ar.website_rule_results(rule)

        context['user_profile']       = user_profile

        return context

class AuditResultGroupRuleWebsiteView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_website.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultGroupRuleWebsiteView, self).get_context_data(**kwargs)

        user        = self.request.user
        result_slug = kwargs['result_slug']
        grouping    = kwargs['grouping']
        group       = kwargs['group']
        rule        = kwargs['rule']
        website     = kwargs['ws']

        user_profile = UserProfile.objects.get(user=user)

        ar   = AuditResult.objects.get(slug=result_slug)
        wsr  = ar.ws_results.get(slug=website)
        wsrr = wsr.ws_rule_results.get(slug=rule)

        if grouping == 'gl':
            group_results      = ar.results_by_guideline()
            group_result       = ar.audit_gl_results.get(slug=group)
        else:
            if grouping == 'rs':
                group_results      = ar.results_by_scope()
                group_result       = ar.audit_rs_results.get(slug=group)
            else:
                group_results      = ar.results_by_rule_category()
                group_result       = ar.audit_rc_results.get(slug=group)
                grouping = 'rc'


        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['grouping']      = grouping
        context['group']         = group
        context['rule']          = Rule.objects.get(slug=rule)

        context['group_results']           = group_results
        context['group_result']            = group_result
        context['group_rule_results']      = ar.group_rule_results(rule)
        context['all_group2_rule_results'] = ar.all_group2_rule_results(rule)
        context['website_rule_results']    = ar.website_rule_results(rule)

        context['website_result']          = wsr
        context['website_rule_result']     = wsrr

        context['user_profile']       = user_profile

        return context

class AuditResultGroupRuleWebsitePageView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultGroupRuleWebsitePageView, self).get_context_data(**kwargs)

        user        = self.request.user
        result_slug = kwargs['result_slug']
        grouping    = kwargs['grouping']
        group       = kwargs['group']
        rule        = kwargs['rule']
        website     = kwargs['ws']
        page        = kwargs['page']

        user_profile = UserProfile.objects.get(user=user)

        ar   = AuditResult.objects.get(slug=result_slug)
        wsr  = ar.ws_results.get(slug=website)
        wsrr = wsr.ws_rule_results.get(slug=rule)
        pr   = wsr.page_all_results.get(id=page)
        prr  = pr.page_rule_results.get(slug=rule)

        if grouping == 'gl':
            group_results      = ar.results_by_guideline()
            group_result       = ar.audit_gl_results.get(slug=group)
        else:
            if grouping == 'rs':
                group_results      = ar.results_by_scope()
                group_result       = ar.audit_rs_results.get(slug=group)
            else:
                group_results      = ar.results_by_rule_category()
                group_result       = ar.audit_rc_results.get(slug=group)
                grouping = 'rc'


        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['grouping']      = grouping
        context['group']         = group
        context['rule']          = Rule.objects.get(slug=rule)

        context['group_results']           = group_results
        context['group_result']            = group_result
        context['group_rule_results']      = ar.group_rule_results(rule)
        context['all_group2_rule_results'] = ar.all_group2_rule_results(rule)
        context['website_rule_results']    = ar.website_rule_results(rule)
        context['website_result']          = wsr
        context['website_rule_result']     = wsrr

        context['page_result']             = pr
        context['page_rule_result']        = prr

        context['user_profile']       = user_profile

        return context
