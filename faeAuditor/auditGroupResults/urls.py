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

file: wensiteResults/urls.py

Author: Jon Gunderson

"""

# reports/urls.py
from __future__ import absolute_import
from django.conf.urls import url

from  .views  import AuditGroupsResultsView
from  .views  import AuditGroupsAuditGroupResultsView

from  .views  import AuditGroupsRuleGroupResultsView
from  .views  import AuditGroupsRuleGroupAuditGroupResultsView

urlpatterns = [

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      AuditGroupsResultsView.as_view(),
      name='audit_groups_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<audit_group_slug>[\w-]+)/$',
      AuditGroupsAuditGroupResultsView.as_view(),
      name='audit_groups_audit_group_results'),


    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group_slug>[\w-]+)/$',
      AuditGroupsRuleGroupResultsView.as_view(),
      name='audit_groups_rule_group_results'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group_slug>[\w-]+)/(?P<website_slug>[\w-]+)/$',
      AuditGroupsRuleGroupAuditGroupResultsView.as_view(),
      name='audit_groups_rule_group_audit_group2_results')

]
