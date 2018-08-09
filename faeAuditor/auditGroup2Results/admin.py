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


from .models import AuditGroup2Result
from .models import AuditGroup2RuleCategoryResult
from .models import AuditGroup2GuidelineResult
from .models import AuditGroup2RuleScopeResult
from .models import AuditGroup2RuleResult


class AuditGroup2ResultAdmin(admin.ModelAdmin):
    list_display = ('group2_item', 'group_result', 'website_count', 'page_count', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_pass_fail_status', 'implementation_score', 'implementation_status')
    list_filter  = ('group2_item', 'group_result')

admin.site.register(AuditGroup2Result, AuditGroup2ResultAdmin)

class AuditGroup2RuleCategoryResultAdmin(admin.ModelAdmin):
    list_display = ('rule_category', 'group2_result', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group2_result', 'rule_category')

admin.site.register(AuditGroup2RuleCategoryResult, AuditGroup2RuleCategoryResultAdmin)

class AuditGroup2GuidelineResultAdmin(admin.ModelAdmin):
    list_display = ('guideline', 'group2_result', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group2_result', 'guideline')

admin.site.register(AuditGroup2GuidelineResult, AuditGroup2GuidelineResultAdmin)

class AuditGroup2RuleScopeResultAdmin(admin.ModelAdmin):
    list_display = ('rule_scope', 'slug', 'group2_result', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group2_result', 'rule_scope')

admin.site.register(AuditGroup2RuleScopeResult, AuditGroup2RuleScopeResultAdmin)

class AuditGroup2RuleResultAdmin(admin.ModelAdmin):
    list_display = ('rule', 'group2_result', 'result_value', 'pages_violation', 'pages_warning', 'pages_manual_check', 'pages_passed', 'pages_na', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group2_result', 'rule')

admin.site.register(AuditGroup2RuleResult, AuditGroup2RuleResultAdmin)
