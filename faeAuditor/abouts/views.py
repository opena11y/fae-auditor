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

File: abouts/views.py

Author: Jon Gunderson

"""


# abouts/views.py

from __future__ import absolute_import
from django.http import HttpResponse
from django.views.generic import TemplateView

from websiteResults.views  import FAENavigationMixin
from ruleCategories.models import RuleCategory


class Disclaimer(FAENavigationMixin, TemplateView):
    template_name = 'abouts/disclaimer.html'

class ConceptsTerms(FAENavigationMixin, TemplateView):
    template_name = 'abouts/concepts_terms.html'

class Overview(FAENavigationMixin, TemplateView):
    template_name = 'abouts/overview.html'

    def get_context_data(self, **kwargs):
        context = super(Overview, self).get_context_data(**kwargs)

        context['rule_categories'] = RuleCategory.objects.all()
        
        return context            


class Privacy(FAENavigationMixin, TemplateView):
    template_name = 'abouts/privacy.html'

class ReportIssues(FAENavigationMixin, TemplateView):
    template_name = 'abouts/report_issues.html'

class Versions(FAENavigationMixin, TemplateView):
    template_name = 'abouts/versions.html'

class Sharing(FAENavigationMixin, TemplateView):
    template_name = 'abouts/sharing.html'
