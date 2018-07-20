
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

from  .views  import Group2ResultsView
from  .views  import Group2ResultsAuditGroup2View
from  .views  import Group2ResultsAuditGroup2WebsiteView
from  .views  import Group2ResultsAuditGroup2WebsitePageView
from  .views  import Group2ResultsAuditGroup2WebsitePageRuleView

from  .views  import Group2RuleGroupResultsView
from  .views  import Group2RuleGroupResultsAuditGroup2View
from  .views  import Group2RuleGroupResultsAuditGroup2WebsiteView
from  .views  import Group2RuleGroupResultsAuditGroup2WebsitePageView
from  .views  import Group2RuleGroupResultsAuditGroup2WebsitePageRuleView


urlpatterns = [

# All rule result views
    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      Group2ResultsView.as_view(),
      name='group2_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      Group2ResultsAuditGroup2View.as_view(),
      name='group2_results_audit_group2'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      Group2ResultsAuditGroup2WebsiteView.as_view(),
      name='group2_results_audit_group2_website'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      Group2ResultsAuditGroup2WebsitePageView.as_view(),
      name='group2_results_audit_group2_website_page'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      Group2ResultsAuditGroup2WebsitePageRuleView.as_view(),
      name='group2_results_audit_group2_website_page_rule'),

    # Rule Group 2

    url(r'^some/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/$',
      Group2RuleGroupResultsView.as_view(),
      name='group2_rule_group_results'),

    url(r'^some/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/$',
      Group2RuleGroupResultsAuditGroup2View.as_view(),
      name='group2_rule_group_results_audit_group2'),

    url(r'^some/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/$',
      Group2RuleGroupResultsAuditGroup2WebsiteView.as_view(),
      name='group2_rule_group_results_audit_group2_website'),

    url(r'^some/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)$',
      Group2RuleGroupResultsAuditGroup2WebsitePageView.as_view(),
      name='group2_rule_group_results_audit_group2_website_page'),

    url(r'^some/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/rg/(?P<rule_group_slug>[\w-]+)/g2/(?P<audit_group2_slug>[\w-]+)/ws/(?P<website_slug>[\w-]+)/pg/(?P<page_num>[\w-]+)/rule/(?P<rule_slug>[\w-]+)$',
      Group2RuleGroupResultsAuditGroup2WebsitePageRuleView.as_view(),
      name='group2_rule_group_results_audit_group2_website_page_rule'),
]
