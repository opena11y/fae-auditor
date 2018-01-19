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

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_label   = "Guideline"
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_label   = "Rule Scope"
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_label   = "Rule Category"
                rule_grouping = 'rc'

        # slugs used for urls
        context['result_slug']    = result_slug
        context['rule_grouping']  = rule_grouping

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_label']   = rule_group_label
        context['rule_group_results'] = rule_group_results

        return context

class AuditResultRuleGroupView(TemplateView):
    template_name = 'auditResults/audit_result_group.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupView, self).get_context_data(**kwargs)

        user           = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']
        rule_group     = kwargs['rule_group']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'

        # slugs used for urls
        context['result_slug']   = result_slug
        context['rule_grouping'] = rule_grouping
        context['rule_group']    = rule_group

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_results'] = rule_group_results
        context['rule_group_result']  = rule_group_result

        return context

class AuditResultRuleGroupRuleView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupRuleView, self).get_context_data(**kwargs)

        user         = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug   = kwargs['result_slug']
        rule_grouping = kwargs['rule_grouping']
        rule_group    = kwargs['rule_group']
        rule_slug     = kwargs['rule_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'


        # slugs used for urls
        context['result_slug']   = result_slug
        context['rule_grouping'] = rule_grouping
        context['rule_group']    = rule_group
        context['rule_slug']     = rule_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_results']      = rule_group_results
        context['rule_group_result']       = rule_group_result
        context['rule']                    = Rule.objects.get(slug=rule_slug)
        context['audit_group_rule_results']      = ar.audit_group_rule_results(rule_slug)
        context['all_audit_group2_rule_results'] = ar.all_audit_group2_rule_results(rule_slug)
        context['website_rule_results']          = ar.website_rule_results(rule_slug)


        return context


class AuditResultRuleGroupRuleWebsiteView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_website.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupRuleWebsiteView, self).get_context_data(**kwargs)

        user        = self.request.user

        result_slug    = kwargs['result_slug']
        rule_grouping  = kwargs['rule_grouping']
        rule_group     = kwargs['rule_group']
        rule_slug      = kwargs['rule_slug']
        website_slug   = kwargs['website_slug']

        user_profile = UserProfile.objects.get(user=user)

        ar   = AuditResult.objects.get(slug=result_slug)
        wsr  = ar.ws_results.get(slug=website_slug)
        wsrr = wsr.ws_rule_results.get(slug=rule_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'


        # slugs used for urls
        context['result_slug']   = result_slug
        context['rule_grouping'] = rule_grouping
        context['rule_group']    = rule_group
        context['rule_slug']     = rule_slug
        context['website_slug']  = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_results']      = rule_group_results
        context['rule_group_result']       = rule_group_result
        context['rule']                    = Rule.objects.get(slug=rule_slug)
        context['website_result']          = wsr
        context['website_rule_result']     = wsrr

        return context

class AuditResultRuleGroupRuleWebsitePageView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_website_page.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupRuleWebsitePageView, self).get_context_data(**kwargs)

        user        = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug   = kwargs['result_slug']
        rule_grouping = kwargs['rule_grouping']
        rule_group    = kwargs['rule_group']
        rule_slug     = kwargs['rule_slug']
        website_slug  = kwargs['website_slug']
        page_num      = kwargs['page_num']

        ar   = AuditResult.objects.get(slug=result_slug)
        wsr  = ar.ws_results.get(slug=website_slug)
        wsrr = wsr.ws_rule_results.get(slug=rule_slug)
        pr   = wsr.page_all_results.get(page_number=page_num)
        prr  = pr.page_rule_results.get(slug=rule_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'


        # slugs used for urls
        context['result_slug']   = result_slug
        context['rule_grouping'] = rule_grouping
        context['rule_group']    = rule_group
        context['rule_slug']     = rule_slug
        context['website_slug']  = website_slug
        context['page_num']      = page_num

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_results']  = rule_group_results
        context['rule_group_result']   = rule_group_result
        context['rule']                = Rule.objects.get(slug=rule_slug)

        context['audit_group_rule_results']      = ar.audit_group_rule_results(rule_slug)
        context['all_audit_group2_rule_results'] = ar.all_audit_group2_rule_results(rule_slug)
        context['website_rule_results']    = ar.website_rule_results(rule_slug)
        context['website_result']          = wsr
        context['website_rule_result']     = wsrr

        context['page_result']             = pr
        context['page_rule_result']        = prr

        return context

class AuditResultRuleGroupRuleAuditGroup2View(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_group2.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupRuleAuditGroup2View, self).get_context_data(**kwargs)

        user        = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group        = kwargs['rule_group']
        rule_slug         = kwargs['rule_slug']
        audit_group2_slug = kwargs['group2_item_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'


        # slugs used for urls
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group']       = rule_group
        context['rule_slug']        = rule_slug
        context['group2_item_slug'] = group2_item_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_results']      = rule_group_results
        context['rule_group_result']       = rule_group_result
        context['rule']                    = Rule.objects.get(slug=rule_slug)
        context['group_rule_results']      = ar.group_rule_results(rule_slug)
        context['all_group2_rule_results'] = ar.all_group2_rule_results(rule_slug)

        return context

class AuditResultRuleGroupRuleAuditGroup2WebsiteView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_group2.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupRuleAuditGroup2WebsiteView, self).get_context_data(**kwargs)

        user        = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group        = kwargs['rule_group']
        rule_slug         = kwargs['rule_slug']
        audit_group2_slug = kwargs['group2_item_slug']
        website_slug      = kwargs['website_slug']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'

        # slugs used for urls
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group']       = rule_group
        context['rule_slug']        = rule_slug
        context['group2_item_slug'] = group2_item_slug
        context['website_slug']     = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile

        context['rule_group_results']      = rule_group_results
        context['rule_group_result']       = rule_group_result
        context['rule']                    = Rule.objects.get(slug=rule_slug)
        context['group_rule_results']      = ar.group_rule_results(rule_slug)
        context['all_group2_rule_results'] = ar.all_group2_rule_results(rule_slug)
        context['website_rule_results']    = ar.website_rule_results(rule_slug, False, audit_group2_slug)

        return context

class AuditResultRuleGroupRuleAuditGroup2WebsitePageView(TemplateView):
    template_name = 'auditResults/audit_result_group_rule_group2.html'

    def get_context_data(self, **kwargs):
        context = super(AuditResultRuleGroupRuleAuditGroup2WebsitePageView, self).get_context_data(**kwargs)

        user        = self.request.user
        user_profile = UserProfile.objects.get(user=user)

        result_slug       = kwargs['result_slug']
        rule_grouping     = kwargs['rule_grouping']
        rule_group        = kwargs['rule_group']
        rule_slug         = kwargs['rule_slug']
        audit_group2_slug = kwargs['group2_item_slug']
        website_slug      = kwargs['website_slug']
        page_num          = kwargs['page_num']

        ar = AuditResult.objects.get(slug=result_slug)

        if rule_grouping == 'gl':
            rule_group_results = ar.audit_gl_results.all()
            rule_group_result  = ar.audit_gl_results.get(slug=rule_group)
        else:
            if rule_grouping == 'rs':
                rule_group_results = ar.audit_rs_results.all()
                rule_group_result       = ar.audit_rs_results.get(slug=rule_group)
            else:
                rule_group_results = ar.audit_rc_results.all()
                rule_group_result  = ar.audit_rc_results.get(slug=rule_group)
                rule_grouping = 'rc'

        # slugs used for urls
        context['result_slug']      = result_slug
        context['rule_grouping']    = rule_grouping
        context['rule_group']       = rule_group
        context['rule_slug']        = rule_slug
        context['group2_item_slug'] = group2_item_slug
        context['website_slug']     = website_slug

        # objects for rendering content
        context['audit']         = ar.audit
        context['audit_result']  = ar
        context['user_profile']  = user_profile


        context['rule_group_results']      = rule_group_results
        context['rule_group_result']       = rule_group_result
        context['rule']                    = Rule.objects.get(slug=rule_slug)

        context['rule_group_rule_results'] = ar.group_rule_results(rule)
        context['all_group2_rule_results'] = ar.all_group2_rule_results(rule)
        context['website_rule_results']    = ar.website_rule_results(rule, False, audit_group2_slug)


        return context
