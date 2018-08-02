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

file: auditResults/urls.py

Author: Jon Gunderson

"""

# reports/urls.py
from __future__ import absolute_import
from django.conf.urls import url

from .views  import AllRulesResultView
from .views  import RuleGroupResultView
from .views  import RuleGroupResultRuleView
from .views  import RuleGroupResultRuleWebsiteView
from .views  import RuleGroupResultRuleWebsitePageView
from .views  import RuleGroupResultRuleAuditGroup2View
from .views  import RuleGroupResultRuleAuditGroup2WebsiteView
from .views  import RuleGroupResultRuleAuditGroup2WebsitePageView
from .views  import RuleGroupResultRuleAuditGroupView
from .views  import RuleGroupResultRuleAuditGroupWebsiteView
from .views  import RuleGroupResultRuleAuditGroupWebsitePageView
from .views  import RuleGroupResultRuleAuditGroupAuditGroup2View
from .views  import RuleGroupResultRuleAuditGroupAuditGroup2WebsiteView
from .views  import RuleGroupResultRuleAuditGroupAuditGroup2WebsitePageView

urlpatterns = [

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      AllRulesResultView.as_view(),
      name='all_rules_result'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/$',
      RuleGroupResultView.as_view(),
      name='rule_group_result'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/$',
      RuleGroupResultRuleView.as_view(),
      name='rule_group_result_rule'),

    # Website result views

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      RuleGroupResultRuleWebsiteView.as_view(),
      name='rule_group_result_rule_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)/$',
      RuleGroupResultRuleWebsitePageView.as_view(),
      name='rule_group_result_rule_website_page'),

    # Audit group result views

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
      RuleGroupResultRuleAuditGroupView.as_view(),
      name='rule_group_result_rule_audit_group'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      RuleGroupResultRuleAuditGroupAuditGroup2View.as_view(),
      name='rule_group_result_rule_audit_group_audit_group2'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      RuleGroupResultRuleAuditGroupWebsiteView.as_view(),
      name='rule_group_result_rule_audit_group_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/$',
      RuleGroupResultRuleAuditGroupWebsitePageView.as_view(),
      name='rule_group_result_rule_audit_group_website_page'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      RuleGroupResultRuleAuditGroupAuditGroup2WebsiteView.as_view(),
      name='rule_group_result_rule_audit_group_audit_group2_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/$',
      RuleGroupResultRuleAuditGroupAuditGroup2WebsitePageView.as_view(),
      name='rule_group_result_rule_audit_group_audit_group2_website_page'),

    # Audit group2 result views

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      RuleGroupResultRuleAuditGroup2View.as_view(),
      name='rule_group_result_rule_audit_group2'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      RuleGroupResultRuleAuditGroup2WebsiteView.as_view(),
      name='rule_group_result_rule_audit_group2_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/$',
      RuleGroupResultRuleAuditGroup2WebsitePageView.as_view(),
      name='rule_group_result_rule_audit_group2_website_page')

]
