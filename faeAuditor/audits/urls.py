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

urlpatterns = [
    url(r'^$',                             AuditsView.as_view(),      name='audits'),
    url(r'^a/(?P<audit_slug>[\w-]+)/$',    AuditView.as_view(),       name='audit'),
    url(r'^run/(?P<audit_slug>[\w-]+)/$',  RunView.as_view(),         name='audit_run'),
    url(r'^processing/$',                  ProcessingView.as_view(),  name='audit_processing')
]
