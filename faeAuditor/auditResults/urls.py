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

file: audits/urls.py

Author: Jon Gunderson

"""

# reports/urls.py
from __future__ import absolute_import
from django.conf.urls import url

from .views  import AuditResultView
from .views  import AuditResultRuleGroupView
from .views  import AuditResultRuleGroupRuleView
from .views  import AuditResultRuleGroupRuleWebsiteView
from .views  import AuditResultRuleGroupRuleWebsitePageView
from .views  import AuditResultRuleGroupRuleAuditGroup2View
from .views  import AuditResultRuleGroupRuleAuditGroup2WebsiteView
from .views  import AuditResultRuleGroupRuleAuditGroup2WebsitePageView

urlpatterns = [

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      AuditResultView.as_view(),
      name='audit_result'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/$',
      AuditResultRuleGroupView.as_view(),
      name='audit_result_rule_group'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/(?P<rule_slug>[\w-]+)$',
      AuditResultRuleGroupRuleView.as_view(),
      name='audit_result_rule_group_rule'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/(?P<rule_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)$',
      AuditResultRuleGroupRuleWebsiteView.as_view(),
      name='audit_result_rule_group_rule_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/(?P<rule_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)$',
      AuditResultRuleGroupRuleWebsitePageView.as_view(),
      name='audit_result_rule_group_rule_website_page'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)$',
      AuditResultRuleGroupRuleAuditGroup2View.as_view(),
      name='audit_result_rule_group_rule_audit_group2'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/(?P<website_slug>[\w-]+)$',
      AuditResultRuleGroupRuleAuditGroup2WebsiteView.as_view(),
      name='audit_result_rule_group_rule_audit_group2_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group>[\w-]+)/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)$',
      AuditResultRuleGroupRuleAuditGroup2WebsitePageView.as_view(),
      name='audit_result_rule_group_rule_audit_group2_website_page')

]
