"""
Copyright 2014-2016 University of Illinois

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

file: faeAuditor/context_processors.py

Author: Jon Gunderson

"""

from __future__ import absolute_import
from django.contrib.sites.models import Site
from userProfiles.models import UserProfile

from faeAuditor.settings import SHIBBOLETH_ENABLED
from faeAuditor.settings import SHIBBOLETH_URL
from faeAuditor.settings import SHIBBOLETH_NAME
from faeAuditor.settings import SELF_REGISTRATION_ENABLED


def site(request):
    return {
        'site': Site.objects.get_current()
    }

def self_registration(request):
	return {
		'self_registration_enabled': SELF_REGISTRATION_ENABLED
	}

def shibboleth(request):
	return {
		'shibboleth': { 'enabled' : SHIBBOLETH_ENABLED,
            'url'  : SHIBBOLETH_URL,
            'name' : SHIBBOLETH_NAME

        }
	}


