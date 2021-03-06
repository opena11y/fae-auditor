"""
Copyright 2014-2018 University of Illinois

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

file: auditResults/urlsCSV.py

Author: Jon Gunderson

"""

# reports/urls.py
from __future__ import absolute_import
from django.conf.urls import url

from .viewsCSV  import AllRulesResultViewCSV
from .viewsCSV  import RuleGroupResultViewCSV
from .viewsCSV  import RuleGroupResultRuleViewCSV

urlpatterns = [

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      AllRulesResultViewCSV,
      name='all_rules_result_csv'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/$',
      RuleGroupResultViewCSV,
      name='rule_group_result_csv'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/$',
      RuleGroupResultRuleViewCSV,
      name='rule_group_result_rule_csv'),

    # url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
    #   RuleGroupResultRuleAuditGroupViewCSV,
    #   name='rule_group_result_rule_audit_group_csv'),
]
