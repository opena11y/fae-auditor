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

from  .views  import GroupResultsView
from  .views  import GroupResultsAuditGroupView

from  .views  import GroupResultsAuditGroupAuditGroup2View
from  .views  import GroupResultsAuditGroupAuditGroup2WebsiteView
from  .views  import GroupResultsAuditGroupAuditGroup2WebsitePageView
from  .views  import GroupResultsAuditGroupAuditGroup2WebsitePageRuleView

from  .views  import GroupResultsAuditGroupWebsiteView
from  .views  import GroupResultsAuditGroupWebsitePageView
from  .views  import GroupResultsAuditGroupWebsitePageRuleView

from  .views  import GroupRuleGroupResultsView
from  .views  import GroupRuleGroupResultsAuditGroupView

from  .views  import GroupRuleGroupResultsAuditGroupAuditGroup2View
from  .views  import GroupRuleGroupResultsAuditGroupAuditGroup2WebsiteView
from  .views  import GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageView
from  .views  import GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageRuleView

from  .views  import GroupRuleGroupResultsAuditGroupWebsiteView
from  .views  import GroupRuleGroupResultsAuditGroupWebsitePageView
from  .views  import GroupRuleGroupResultsAuditGroupWebsitePageRuleView

urlpatterns = [

# All rule result views
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      GroupResultsView.as_view(),
      name='group_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
      GroupResultsAuditGroupView.as_view(),
      name='group_results_audit_group'),

# All rules audit group 2 views (website grouping by audit group and audit group 2)
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      GroupResultsAuditGroupAuditGroup2View.as_view(),
      name='group_results_audit_group_audit_group2'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      GroupResultsAuditGroupAuditGroup2WebsiteView.as_view(),
      name='group_results_audit_group_audit_group2_website'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      GroupResultsAuditGroupAuditGroup2WebsitePageView.as_view(),
      name='group_results_audit_group_audit_group2_website_page'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      GroupResultsAuditGroupAuditGroup2WebsitePageRuleView.as_view(),
      name='group_results_audit_group_audit_group2_website_page_rule'),


# All rules website views (website grouping by audit group only)
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      GroupResultsAuditGroupWebsiteView.as_view(),
      name='group_results_audit_group_website'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      GroupResultsAuditGroupWebsitePageView.as_view(),
      name='group_results_audit_group_website_page'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      GroupResultsAuditGroupWebsitePageRuleView.as_view(),
      name='group_results_audit_group_website_page_rule'),


# Rule grouping result views
    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/$',
      GroupRuleGroupResultsView.as_view(),
      name='group_rule_group_results'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/$',
      GroupRuleGroupResultsAuditGroupView.as_view(),
      name='group_rule_group_results_audit_group'),


# Rule grouping audit group 2 views (website grouping by audit group and audit group 2)

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      GroupRuleGroupResultsAuditGroupAuditGroup2View.as_view(),
      name='group_rule_group_results_audit_group_audit_group2'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      GroupRuleGroupResultsAuditGroupAuditGroup2WebsiteView.as_view(),
      name='group_rule_group_results_audit_group_audit_group2_website'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageView.as_view(),
      name='group_rule_group_results_audit_group_audit_group2_website_page'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g/(?P<audit_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      GroupRuleGroupResultsAuditGroupAuditGroup2WebsitePageRuleView.as_view(),
      name='group_rule_group_results_audit_group_audit_group2_website_page_rule'),

# Rule grouping website views

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      GroupRuleGroupResultsAuditGroupWebsiteView.as_view(),
      name='group_rule_group_results_audit_group_website'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      GroupRuleGroupResultsAuditGroupWebsitePageView.as_view(),
      name='group_rule_group_results_audit_group_website_page'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)g/(?P<audit_group_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      GroupRuleGroupResultsAuditGroupWebsitePageRuleView.as_view(),
      name='group_rule_group_results_audit_group_website_page_rule')


]
