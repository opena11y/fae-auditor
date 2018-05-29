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

from .views  import AuditResultView
from .views  import AuditResultRuleGroupView
from .views  import AuditResultRuleGroupRuleView
from .views  import AuditResultRuleGroupRuleWebsiteView
from .views  import AuditResultRuleGroupRuleWebsitePageView
from .views  import AuditResultRuleGroupRuleAuditGroup2View
from .views  import AuditResultRuleGroupRuleAuditGroup2WebsiteView
from .views  import AuditResultRuleGroupRuleAuditGroup2WebsitePageView
from .views  import AuditResultRuleGroupRuleAuditGroupView
from .views  import AuditResultRuleGroupRuleAuditGroupWebsiteView
from .views  import AuditResultRuleGroupRuleAuditGroupWebsitePageView
from .views  import AuditResultRuleGroupRuleAuditGroupAuditGroup2View
from .views  import AuditResultRuleGroupRuleAuditGroupAuditGroup2WebsiteView
from .views  import AuditResultRuleGroupRuleAuditGroupAuditGroup2WebsitePageView

urlpatterns = [

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      AuditResultView.as_view(),
      name='audit_result'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/$',
      AuditResultRuleGroupView.as_view(),
      name='audit_result_rule_group'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleView.as_view(),
      name='audit_result_rule_group_rule'),

    # Website result views

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleWebsiteView.as_view(),
      name='audit_result_rule_group_rule_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)/$',
      AuditResultRuleGroupRuleWebsitePageView.as_view(),
      name='audit_result_rule_group_rule_website_page'),

    # Audit group result views

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroupView.as_view(),
      name='audit_result_rule_group_rule_audit_group'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroupAuditGroup2View.as_view(),
      name='audit_result_rule_group_rule_audit_group_audit_group2'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroupWebsiteView.as_view(),
      name='audit_result_rule_group_rule_audit_group_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroupWebsitePageView.as_view(),
      name='audit_result_rule_group_rule_audit_group_website_page'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroupAuditGroup2WebsiteView.as_view(),
      name='audit_result_rule_group_rule_audit_group_audit_group2_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroupAuditGroup2WebsitePageView.as_view(),
      name='audit_result_rule_group_rule_audit_group_audit_group2_website_page'),

    # Audit group2 result views

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroup2View.as_view(),
      name='audit_result_rule_group_rule_audit_group2'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroup2WebsiteView.as_view(),
      name='audit_result_rule_group_rule_audit_group2_website'),

    url(r'^(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/rule/(?P<rule_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/$',
      AuditResultRuleGroupRuleAuditGroup2WebsitePageView.as_view(),
      name='audit_result_rule_group_rule_audit_group2_website_page')

]
