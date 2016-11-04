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
from .uid import generate

from django.views.generic import TemplateView
from django.views.generic import CreateView 
from django.views.generic import FormView 
from django.views.generic import RedirectView

from django.contrib.auth.models import User

from .models import Audit
from userProfiles.models import UserProfile


from django.utils.http import is_safe_url
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, RedirectView

from auditResults.models import AuditResult


# ==============================================================
#
# Audit views
#
# ==============================================================

class AuditsView(LoginRequiredMixin, TemplateView):
    template_name = 'audits/audits.html'

    def get_context_data(self, **kwargs):
        context = super(AuditsView, self).get_context_data(**kwargs)

        user = self.request.user

        user_profile = UserProfile.objects.get(user=user)

        audits = Audit.objects.filter(user=user)

        context['audits']       = audits
        context['user_profile']  = user_profile
        
        return context            

class AuditView(LoginRequiredMixin, TemplateView):
    template_name = 'audits/audit.html'

    def get_context_data(self, **kwargs):
        context = super(AuditView, self).get_context_data(**kwargs)

        user = self.request.user

        user_profile = UserProfile.objects.get(user=user)

        audit = Audit.objects.get(user=user, id=kwargs['audit_id'])

        context['audit']         = audit
        context['user_profile']  = user_profile
        
        return context              

class RunView(LoginRequiredMixin, CreateView):

    model = AuditResult
    fields = ['title', 'ruleset', 'depth', 'follow', 'max_pages', 'wait_time']
    audit_id = None

    template_name = 'audits/run.html'

    success_url = reverse_lazy('audit_processing')

    def form_valid(self, form):
        user     = self.request.user
        audit_id = self.kwargs.get('audit_id', None) 
        audit = Audit.objects.get(id=audit_id)

        form.instance.user = self.request.user
        if form.instance.depth == 1:
          form.instance.follow = 1

        form.instance.user = user
        form.instance.slug = generate()
        form.instance.audit = audit        
        form.instance.browser_emulation = audit.browser_emulation

        print("Valid")

        return super(RunView, self).form_valid(form)

    def form_invalid(self, form):

        user     = self.request.user
        audit_id = self.kwargs.get('audit_id', None) 

        print("Invalid")

        return super(RunView, self).form_invalid(form)
  
    def get_context_data(self, **kwargs):
        context = super(RunView, self).get_context_data(**kwargs)

        user     = self.request.user
        audit_id = self.kwargs.get('audit_id', None) 

        user_profile = UserProfile.objects.get(user=user)
        audit = Audit.objects.get(user=user, id=audit_id)

        context['audit'] = audit
        context['user_profile'] = user_profile

        return context              

class ProcessingView(LoginRequiredMixin, TemplateView):
    template_name = 'audits/processing.html'

    def get_context_data(self, **kwargs):
        context = super(ProcessingView, self).get_context_data(**kwargs)

        audit_results = AuditResult.objects.filter(user=self.request.user)

        user_profile = UserProfile.objects.get(user=self.request.user)
        context['audit_results_processing'] = audit_results.exclude(status='C').exclude(status='E').exclude(status='SUM').order_by('-created')
        context['audit_results_complete']   = audit_results.filter(status='C').order_by('-created')[:2]
        
        return context    

