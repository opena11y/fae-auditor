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

from .views import AuditsView
from .views import AuditView
from .views import RunView
from .views import ProcessingView

from auditResults.views  import AuditResultView
from auditResults.views  import AuditResultGroupView
from auditResults.views  import AuditResultGroupRuleView
from auditResults.views  import AuditResultGroupRuleWebsiteView
from auditResults.views  import AuditResultGroupRuleWebsitePageView

urlpatterns = [
    url(r'^$',                             AuditsView.as_view(),      name='audits'),
    url(r'^a/(?P<audit_slug>[\w-]+)/$',    AuditView.as_view(),       name='audit'),
    url(r'^run/(?P<audit_slug>[\w-]+)/$',  RunView.as_view(),         name='audit_run'),
    url(r'^processing/$',                  ProcessingView.as_view(),  name='audit_processing'),

    url(r'^ar/(?P<result_slug>[\w-]+)/(?P<grouping>[\w-]+)/$',
      AuditResultView.as_view(),
      name='audit_result'),

    url(r'^ar/(?P<result_slug>[\w-]+)/(?P<grouping>[\w-]+)/(?P<group>[\w-]+)/$',
      AuditResultGroupView.as_view(),
      name='audit_result_group'),

    url(r'^ar/(?P<result_slug>[\w-]+)/(?P<grouping>[\w-]+)/(?P<group>[\w-]+)/(?P<rule>[\w-]+)$',
      AuditResultGroupRuleView.as_view(),
      name='audit_result_group_rule'),

    url(r'^ar/(?P<result_slug>[\w-]+)/(?P<grouping>[\w-]+)/(?P<group>[\w-]+)/(?P<rule>[\w-]+)/ws/(?P<ws>[\w-]+)$',
      AuditResultGroupRuleWebsiteView.as_view(),
      name='audit_result_group_rule_website'),

    url(r'^ar/(?P<result_slug>[\w-]+)/(?P<grouping>[\w-]+)/(?P<group>[\w-]+)/(?P<rule>[\w-]+)/ws/(?P<ws>[\w-]+)/(?P<page>[\w-]+)$',
      AuditResultGroupRuleWebsitePageView.as_view(),
      name='audit_result_group_rule_website_page')

]
