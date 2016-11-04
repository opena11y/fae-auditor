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

file: userProfiles/models.py

Author: Jon Gunderson

"""

from __future__                 import absolute_import
from django.db                  import models
from django.contrib.auth.models import User
from registration.signals       import user_registered
from timezone_field             import TimeZoneField


from websiteResults.models      import WebsiteResult
# from stats.models               import StatsUser
from django.contrib.sites.models import Site


from django.core.urlresolvers import reverse
from django.template.loader   import render_to_string

from django.db.models import Q

from django.contrib import messages

import markdown

from django.core.mail import send_mail
from faeAuditor.settings import EMAIL_HOST_USER
from faeAuditor.settings import ADMIN_EMAIL

from datetime import datetime 

from datetime import date

from accounts.models  import AccountType


SUBSCRIPTION_STATUS_CHOICES = (
    ('FREE',    'Free'),
    ('CURRENT',  'Current'),
    ('EXPIRED',  'Expired')
)

class UserProfile(models.Model):

    user          = models.OneToOneField(User, related_name="profile")

    account_type             = models.ForeignKey(AccountType, related_name="user_profiles")
    
    subscription_start      = models.DateField(null=True, blank=True)
    subscription_end        = models.DateField(null=True, blank=True)
    subscription_payments   = models.IntegerField(default=0) # in dollars
    subscription_daily_rate = models.IntegerField(default=0) # in cents
    subscription_status     = models.CharField(max_length=8, choices=SUBSCRIPTION_STATUS_CHOICES, default="CURRENT")
    subscription_days       = models.IntegerField(default=0)

    org                 = models.CharField(max_length=128, blank=True)
    dept                = models.CharField(max_length=128, blank=True)
    email_announcements = models.BooleanField(default=True)

    timezone = TimeZoneField(default='America/Chicago')
    
    def __unicode__(self):
        return self.user.username  




    
 