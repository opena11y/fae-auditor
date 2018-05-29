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

file: auditGroupResults/urls.py

Author: Jon Gunderson

"""

# reports/urls.py
from __future__ import absolute_import
from django.conf.urls import url

from  .views  import AuditGroupsResultsView
from  .views  import AuditGroupsAuditGroupResultsView

from  .views  import AuditGroupsAuditGroupAuditGroup2ResultsView
from  .views  import AuditGroupsAuditGroupAuditGroup2WebsiteResultsView
from  .views  import AuditGroupsAuditGroupAuditGroup2WebsitePageResultsView
from  .views  import AuditGroupsAuditGroupAuditGroup2WebsitePageRuleResultsView

from  .views  import AuditGroupsAuditGroupWebsiteResultsView
from  .views  import AuditGroupsAuditGroupWebsitePageResultsView
from  .views  import AuditGroupsAuditGroupWebsitePageRuleResultsView

from  .views  import AuditGroupsRuleGroupResultsView
from  .views  import AuditGroupsRuleGroupAuditGroupResultsView
from  .views  import AuditGroupsRuleGroupAuditGroupAuditGroup2ResultsView
from  .views  import AuditGroupsRuleGroupAuditGroupWebsiteResultsView

urlpatterns = [

# All rule result views
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      AuditGroupsResultsView.as_view(),
      name='audit_groups_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
      AuditGroupsAuditGroupResultsView.as_view(),
      name='audit_groups_audit_group_results'),

# All rules audit group 2 views (website grouping by audit group and audit group 2)
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      AuditGroupsAuditGroupAuditGroup2ResultsView.as_view(),
      name='audit_groups_audit_group_audit_group2_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditGroupsAuditGroupAuditGroup2WebsiteResultsView.as_view(),
      name='audit_groups_audit_group_audit_group2_website_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      AuditGroupsAuditGroupAuditGroup2WebsitePageResultsView.as_view(),
      name='audit_groups_audit_group_audit_group2_website_page_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      AuditGroupsAuditGroupAuditGroup2WebsitePageRuleResultsView.as_view(),
      name='audit_groups_audit_group_audit_group2_website_page_results'),


# All rules website views (website grouping by audit group only)
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditGroupsAuditGroupWebsiteResultsView.as_view(),
      name='audit_groups_audit_group_website_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      AuditGroupsAuditGroupWebsitePageResultsView.as_view(),
      name='audit_groups_audit_group_website_page_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      AuditGroupsAuditGroupWebsitePageRuleResultsView.as_view(),
      name='audit_groups_audit_group_website_page_rule_results'),


# Rule grouping views
    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/$',
      AuditGroupsRuleGroupResultsView.as_view(),
      name='audit_groups_rule_group_results'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
      AuditGroupsRuleGroupAuditGroupResultsView.as_view(),
      name='audit_groups_rule_group_audit_group_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      AuditGroupsRuleGroupAuditGroupAuditGroup2ResultsView.as_view(),
      name='audit_groups_rule_group_audit_group_audit_group2_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      AuditGroupsRuleGroupAuditGroupWebsiteResultsView.as_view(),
      name='audit_groups_rule_group_audit_group_website_results')


]
