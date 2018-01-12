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

file: websiteResults/admin.py

Author: Jon Gunderson

"""

from __future__ import absolute_import
from django.contrib import admin


from .models import WebsiteResult
from .models import WebsiteRuleCategoryResult
from .models import WebsiteGuidelineResult
from .models import WebsiteRuleScopeResult
from .models import WebsiteRuleResult

from .models import ProcessedURL
from .models import UnprocessedURL
from .models import FilteredURL

class WebsiteResultAdmin(admin.ModelAdmin):
    list_display = ('url', 'audit_result', 'title', 'status', 'slug', 'archive', 'ruleset', 'depth', 'created', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_score', 'implementation_status')
    list_filter  = ('status', 'audit_result')

admin.site.register(WebsiteResult, WebsiteResultAdmin)

class WebsiteRuleCategoryResultAdmin(admin.ModelAdmin):
    list_display = ('rule_category', 'slug', 'ws_report', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('ws_report', 'rule_category')

admin.site.register(WebsiteRuleCategoryResult, WebsiteRuleCategoryResultAdmin)

class WebsiteGuidelineResultAdmin(admin.ModelAdmin):
    list_display = ('guideline', 'slug', 'ws_report', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('ws_report', 'guideline')

admin.site.register(WebsiteGuidelineResult, WebsiteGuidelineResultAdmin)

class WebsiteRuleScopeResultAdmin(admin.ModelAdmin):
    list_display = ('rule_scope', 'slug', 'ws_report', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('ws_report', 'rule_scope')

admin.site.register(WebsiteRuleScopeResult, WebsiteRuleScopeResultAdmin)

class WebsiteRuleResultAdmin(admin.ModelAdmin):
    list_display = ('rule', 'ws_report', 'result_value', 'pages_violation', 'pages_warning', 'pages_manual_check', 'pages_passed', 'pages_na', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('ws_report', 'rule')

admin.site.register(WebsiteRuleResult, WebsiteRuleResultAdmin)

class ProcessedURLAdmin(admin.ModelAdmin):
    list_display = ('page_seq_num', 'url_requested', 'url_returned')
    list_filter  = ('ws_report',)

admin.site.register(ProcessedURL, ProcessedURLAdmin)

class UnprocessedURLAdmin(admin.ModelAdmin):
    list_display = ('url', 'url_referenced')
    list_filter  = ('ws_report',)

admin.site.register(UnprocessedURL, UnprocessedURLAdmin)

class FilteredURLAdmin(admin.ModelAdmin):
    list_display = ('url', 'url_referenced')
    list_filter  = ('ws_report',)

admin.site.register(FilteredURL, FilteredURLAdmin)

