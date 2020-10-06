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

from django.urls import reverse_lazy, reverse
from django.contrib.auth.mixins import LoginRequiredMixin
from audits.uid import generate

from audits.resultNavigationMixin import ResultNavigationMixin

# ==============================================================
#
# Website Report Views
#
# ==============================================================

def WebsiteResultsViewCSV(request, result_slug, rule_grouping):

    ar = AuditResult.objects.get(slug=result_slug)

    wsrs = ar.ws_results.filter(status='C')

    content = "<pre>"
    content += '"All Rules Website Results View"'
    content += '\n'

    content += wsrs[0].csvColumnHeaders()

    for wsr in wsrs:
        content += wsr.toCSV()

    return HttpResponse(content, content_type="text/html")
