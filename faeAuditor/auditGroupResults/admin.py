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


from .models import AuditGroupResult
from .models import AuditGroupRuleCategoryResult
from .models import AuditGroupGuidelineResult
from .models import AuditGroupRuleScopeResult
from .models import AuditGroupRuleResult


class AuditGroupResultAdmin(admin.ModelAdmin):
    list_display = ('group_item', 'audit_result', 'website_count', 'page_count', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_pass_fail_status', 'implementation_score', 'implementation_status')
    list_filter  = ('group_item', 'audit_result')

admin.site.register(AuditGroupResult, AuditGroupResultAdmin)

class AuditGroupRuleCategoryResultAdmin(admin.ModelAdmin):
    list_display = ('rule_category', 'group_result', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group_result', 'rule_category')

admin.site.register(AuditGroupRuleCategoryResult, AuditGroupRuleCategoryResultAdmin)

class AuditGroupGuidelineResultAdmin(admin.ModelAdmin):
    list_display = ('guideline', 'group_result', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group_result', 'guideline')

admin.site.register(AuditGroupGuidelineResult, AuditGroupGuidelineResultAdmin)

class AuditGroupRuleScopeResultAdmin(admin.ModelAdmin):
    list_display = ('rule_scope', 'group_result', 'rules_violation', 'rules_warning', 'rules_manual_check', 'rules_passed', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group_result', 'rule_scope')

admin.site.register(AuditGroupRuleScopeResult, AuditGroupRuleScopeResultAdmin)

class AuditGroupRuleResultAdmin(admin.ModelAdmin):
    list_display = ('rule', 'slug', 'group_result', 'result_value', 'pages_violation', 'pages_warning', 'pages_manual_check', 'pages_passed', 'pages_na', 'implementation_pass_fail_score', 'implementation_score', 'implementation_status')
    list_filter  = ('group_result', 'rule')

admin.site.register(AuditGroupRuleResult, AuditGroupRuleResultAdmin)


