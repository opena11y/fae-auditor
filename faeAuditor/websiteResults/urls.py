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

from .views  import WebsiteResultsView
from .views  import WebsiteResultsWebsiteView
from .views  import WebsiteResultsWebsiteInfoView
from .views  import WebsiteResultsWebsitePageView
from .views  import WebsiteResultsWebsitePageRuleView

from .views  import WebsiteRuleGroupResultsView
from .views  import WebsiteRuleGroupResultsWebsiteView
from .views  import WebsiteRuleGroupResultsWebsitePageView
from .views  import WebsiteRuleGroupResultsWebsitePageRuleView

urlpatterns = [

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<website_slug>[\w-]+)/info/$',
      WebsiteResultsWebsiteInfoView.as_view(),
      name='website_results_website_info'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/$',
      WebsiteResultsView.as_view(),
      name='website_results'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<website_slug>[\w-]+)/$',
      WebsiteResultsWebsiteView.as_view(),
      name='website_results_website'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)/$',
      WebsiteResultsWebsitePageView.as_view(),
      name='website_results_website_page'),

    url(r'^all/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)/(?P<rule_slug>[\w-]+)/$',
      WebsiteResultsWebsitePageRuleView.as_view(),
      name='website_results_website_page_rule'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group_slug>[\w-]+)/$',
      WebsiteRuleGroupResultsView.as_view(),
      name='website_rule_group_results'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group_slug>[\w-]+)/(?P<website_slug>[\w-]+)/$',
      WebsiteRuleGroupResultsWebsiteView.as_view(),
      name='website_rule_group_results_website'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group_slug>[\w-]+)/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)/$',
      WebsiteRuleGroupResultsWebsitePageView.as_view(),
      name='website_rule_group_results_website_page'),

    url(r'^rg/(?P<result_slug>[\w-]+)/(?P<rule_grouping>[\w-]+)/(?P<rule_group_slug>[\w-]+)/(?P<website_slug>[\w-]+)/(?P<page_num>[\w-]+)/(?P<rule_slug>[\w-]+)/$',
      WebsiteRuleGroupResultsWebsitePageRuleView.as_view(),
      name='website_rule_group_results_website_page_rule'),



]
