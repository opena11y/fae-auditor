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

file: faeAuditor/base.py

Author: Jon Gunderson

"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
from __future__ import print_function
from __future__ import absolute_import
import json

from django.core.exceptions import ImproperlyConfigured
from os.path import join, abspath, dirname
import registration.backends.default

SITE_ID = 1
DEFAULT_CHARSET='utf-8'

here = lambda *dirs: join(abspath(dirname(__file__)), *dirs)
root = lambda *dirs: join(abspath(here("..","..")), *dirs)

BASE_DIR = here("", "")
print("BASE_DIR: " + BASE_DIR)

APP_DIR  = root("")
print(" APP_DIR: " + APP_DIR)


# JSON-based secrets module
with open(join(BASE_DIR,"secrets.json")) as f:
    secrets = json.loads(f.read())


def get_secret(setting, secrets=secrets):
    """(Get the secret variable or return explicit exception.)"""
    try:
        return secrets[setting]
    except KeyError:
        error_msg = "Set the {0} enviroment variable".format(setting)
        raise ImproperlyConfigured


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = get_secret('DEBUG')

EMAIL_HOST               = get_secret('EMAIL_HOST')

EMAIL_PORT               = get_secret('EMAIL_PORT')
EMAIL_USE_TLS            = get_secret('EMAIL_USE_TLS')

EMAIL_HOST_USER          = get_secret('EMAIL_HOST_USER')
EMAIL_HOST_USER_PASSWORD = get_secret('EMAIL_HOST_USER_PASSWORD')

DEFAULT_FROM_EMAIL       = get_secret('EMAIL_HOST_USER')
SERVER_EMAIL             = get_secret('EMAIL_HOST_USER')

if get_secret('SITE_URL').find('127.0.0.1') >= 0 or get_secret('SITE_URL').find('localhost') >= 0:
  EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
else:  
  EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

ACCOUNT_ACTIVATION_DAYS = get_secret('ACCOUNT_ACTIVATION_DAYS')
REGISTRATION_EMAIL_HTML = False

ALLOWED_HOSTS = get_secret('ALLOWED_HOSTS')

SELF_REGISTRATION_ENABLED = get_secret('SELF_REGISTRATION_ENABLED')
SHIBBOLETH_ENABLED        = get_secret('SHIBBOLETH_ENABLED')

if SHIBBOLETH_ENABLED:
    SHIBBOLETH_URL            = get_secret('SHIBBOLETH_URL')
    SHIBBOLETH_NAME           = get_secret('SHIBBOLETH_NAME')
    SHIBBOLETH_SUPERUSER      = get_secret('SHIBBOLETH_SUPERUSER')
else:    
    SHIBBOLETH_URL            = ''
    SHIBBOLETH_NAME           = ''
    SHIBBOLETH_SUPERUSER      = ''

SITE_NAME = get_secret('SITE_NAME')
SITE_URL  = get_secret('SITE_URL')

ADMIN_USER_NAME          = get_secret('ADMIN_USER_NAME')
ADMIN_FIRST_NAME         = get_secret('ADMIN_FIRST_NAME')
ADMIN_LAST_NAME          = get_secret('ADMIN_LAST_NAME')
ADMIN_PASSWORD           = get_secret('ADMIN_PASSWORD')
ADMIN_EMAIL              = get_secret('ADMIN_EMAIL')
ANONYMOUS_PASSWORD       = get_secret('ANONYMOUS_PASSWORD')
DEFAULT_ACCOUNT_TYPE     = get_secret('DEFAULT_ACCOUNT_TYPE')


# Application definition

PROCESSING_THREADS = get_secret('PROCESSING_THREADS')

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'abouts.apps.AboutsConfig',
    'accounts.apps.AccountsConfig',
    'markup.apps.MarkupConfig',
    'markupInfo.apps.MarkupInfoConfig',
    'pageResults.apps.PageResultsConfig',
    'ruleCategories.apps.RuleCategoriesConfig',
    'rules.apps.RulesConfig',
    'rulesets.apps.RulesetsConfig',
    'wcag20.apps.WCAG20Config',
    'userProfiles.apps.UserprofilesConfig',
    'contacts.apps.ContactsConfig',
    'audits.apps.AuditsConfig',
    'auditResults.apps.AuditResultsConfig',
    'auditGroupResults.apps.AuditGroupResultsConfig',
    'auditGroup2Results.apps.AuditGroup2ResultsConfig',
    'websiteResults.apps.WebsiteResultsConfig',
)



if SHIBBOLETH_ENABLED:
    MIDDLEWARE_CLASSES = (
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
        'django.contrib.auth.middleware.PersistentRemoteUserMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
        'django.middleware.security.SecurityMiddleware',
    )

    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.RemoteUserBackend',
    )


    LOGIN_URL = SHIBBOLETH_URL


else:
    MIDDLEWARE_CLASSES = (
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.auth.middleware.RemoteUserMiddleware',    
        'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
        'django.middleware.security.SecurityMiddleware',
    )

ROOT_URLCONF = 'faeAuditor.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [join(BASE_DIR, 'templates/')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.template.context_processors.tz',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'faeAuditor.context_processors.site',
                'faeAuditor.context_processors.self_registration',
                'faeAuditor.context_processors.shibboleth',
            ],
        },
    },
]

WSGI_APPLICATION = 'faeAuditor.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

DATABASES = {
    'default': {
          'ENGINE' : 'django.db.backends.postgresql_psycopg2', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
            'NAME' : get_secret('DATABASE_NAME'),              # Or path to database file if using sqlite3.
            'USER' : get_secret('DATABASE_USER'),              # Not used with sqlite3.
        'PASSWORD' : get_secret('DATABASE_PASSWORD'),          # Not used with sqlite3.
            'HOST' : get_secret('DATABASE_HOST'),              # Set to empty string for localhost. Not used with sqlite3.
            'PORT' : get_secret('DATABASE_PORT'),              # Set to empty string for default. Not used with sqlite3.
    }
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': get_secret('LOGGER_LEVEL'),
            'class': 'logging.FileHandler',
            'filename': join(APP_DIR, 'logs/faeAuditor_log'),
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': get_secret('LOGGER_LEVEL'),
            'propagate': True,
        },
    },
}

# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'America/Chicago'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = join(BASE_DIR, 'static/')

print('STATIC ROOT: ' + STATIC_ROOT)

STATICFILES_DIRS = (
  join(APP_DIR, "faeAuditor/static"),
)

LOGIN_REDIRECT_URL='/'
