from datetime import datetime
from audits.uid      import generate


from django.db import models

from rulesets.models   import Ruleset

from django.contrib.auth.models import User

      
RULESET_CHOICES = (
  ('ARIA_TRANS',  'WCAG + Landmarks'),
  ('ARIA_STRICT', 'WCAG + ARIA')
)

FOLLOW_CHOICES = (
  (1, 'Specified domain only'),
  (2, 'Next-level subdomains')
)

BROWSER_CHOICES = (
  ('Firefox',  'Mozilla Firefox'),
  ('IE',       'Microsoft Internet Explorer'),
  ('Chrome',   'Google Chrome' )
)

DEPTH_CHOICES = (
  (1, 'Start URL only'),
  (2, 'First level links'),
  (3, 'Second level links')
)

MAX_PAGES_CHOICES = (
  (   5, '   5 pages'),
  (  10, '  10 pages'),
  (  25, '  25 pages'),
  (  50, '  50 pages'),
  ( 100, ' 100 pages'),
  ( 200, ' 200 pages'),
  ( 400, ' 400 pages'),
  ( 800, ' 800 pages')
)  
      
WAIT_TIME_CHOICES = (
  (30000,  ' 30 seconds'),
  (45000,  ' 45 seconds'),
  (60000,  ' 60 seconds'),
  (90000,  ' 90 seconds'),
  (120000, '120 seconds')
)            
      
class Audit(models.Model):

  id       = models.AutoField(primary_key=True)
  user     = models.ForeignKey(User)
  created  = models.DateTimeField(auto_now_add=True, editable=False)

  slug   = models.SlugField(max_length=50, blank=True)

  title             = models.CharField('Audit Title', max_length=512)
  
  ruleset           = models.ForeignKey(Ruleset)
  depth             = models.IntegerField(default=2, choices=DEPTH_CHOICES)
  max_pages         = models.IntegerField("Maximum Pages", choices=MAX_PAGES_CHOICES, default=0, blank=False)
  wait_time         = models.IntegerField(default=30000, choices=WAIT_TIME_CHOICES)
  browser_emulation = models.CharField("Browser Emulation", max_length=32, choices=BROWSER_CHOICES, default="Chrome") 
  follow            = models.IntegerField("Follow Links in", choices=FOLLOW_CHOICES, default=1, blank=False)
 
  class Meta:
    verbose_name        = "Audit"
    verbose_name_plural = "Audits"
    ordering = ['title']
    

  def __unicode__(self):
      return "Audit: " + self.title      

  @models.permalink
  def get_show_audit_url(self):
    return ('show_audit', [self.id])        

  @models.permalink
  def get_audit_start_url(self):
    return ('audit_start', [self.id])        
            
  def get_website_count(self):
    count = len(this.websites.all())
    return count    

  def has_audit_results(self):
    return (len(self.audit_results.all()) > 0)   
    
  def is_processing(self):
    try:
      ars = self.audit_results.all()
      
      for ar in ars:
        if not ar.is_added():
          return True
      
      return False
    except: 
      return False

  def get_processing_status(self):
    try:
      ars = self.audit_results.all()
      
      for ar in ars:
        if not ar.is_complete():
          return ar.show_audit_status()
      
      return ar.show_audit_status()
    except: 
      return ""     

  def is_processing(self):
    ars = self.audit_results.all()
      
    for ar in ars:
      if not ar.is_added():
        return True
      
    return False

  def get_processing_reports(self):
    ra = []
    
    ars = self.audit_results.all()
      
    for ar in ars:
      if not ar.is_added():
        ra.append(ar)
      
    return ra
      
  def get_complete_reports(self):
    ra = []
    
    ars = self.audit_results.all()
      
    for ar in ars:
      if ar.is_added():
        ra.append(ar)
      
    return ra
          
      

class AuditGroup(models.Model):

  id     = models.AutoField(primary_key=True)

  audit  = models.ForeignKey(Audit, related_name="groups")

  slug   = models.SlugField(max_length=50, blank=True)
  
  title  = models.CharField('Group Title',  max_length=512, default="no group title")

  position  = models.IntegerField('Position', default=0)
  
  class Meta:
    verbose_name        = "Audit Group"
    verbose_name_plural = "Audit Groups"
    ordering = ['audit']

  def __unicode__(self):
      return self.title
  
class AuditGroupItem(models.Model):

  id     = models.AutoField(primary_key=True)

  group  = models.ForeignKey(AuditGroup, related_name="group_items")

  slug   = models.SlugField(max_length=50, blank=True)    
  title = models.CharField('Group Item Title',  max_length=512, default="no group item title")
  
  class Meta:
    verbose_name        = "Audit Group Item"
    verbose_name_plural = "Audit Groups Items"
    ordering = ['group']

  def __unicode__(self):
      return self.title
  

class AuditGroup2(models.Model):

  id     = models.AutoField(primary_key=True)

  audit  = models.ForeignKey(Audit, related_name="group2s")

  slug   = models.SlugField(max_length=50, blank=True)
  
  title  = models.CharField('Group 2 Title',  max_length=512, default="no group 2 title")

  position  = models.IntegerField('Position', default=0)
  
  class Meta:
    verbose_name        = "Audit Group 2"
    verbose_name_plural = "Audit Group 2s"
    ordering = ['audit']

  def __unicode__(self):
      return self.title
  
class AuditGroup2Item(models.Model):

  id     = models.AutoField(primary_key=True)

  group2     = models.ForeignKey(AuditGroup2,    related_name="group2_items")
  group_item = models.ForeignKey(AuditGroupItem, related_name="group2_items")
  
  slug   = models.SlugField(max_length=50, blank=True)
   
  title = models.CharField('Group2 Item Title',  max_length=512, default="no group group item title")
  
  class Meta:
    verbose_name        = "Audit Group2 Item"
    verbose_name_plural = "Audit Groups2 Items"
    ordering = ['group2', 'group_item']

  def __unicode__(self):
      return self.title
  

class Website(models.Model):

  id     = models.AutoField(primary_key=True)

  audit = models.ForeignKey(Audit, related_name="websites")
  group_item = models.ForeignKey(AuditGroupItem, related_name="websites", null=True, blank=True)
  group2_item = models.ForeignKey(AuditGroup2Item, related_name="websites", null=True, blank=True)
  
  url    = models.URLField('Website URL',     max_length=1024)
  title  = models.CharField('Website Title',  max_length=512, default="no title")
  slug   = models.SlugField(max_length=128, blank=True)  # used as a slug
  
  span_sub_domains      = models.CharField("Span Domains (space separated)",    max_length=1024, default="", blank=True)
  exclude_sub_domains   = models.CharField("Exclude Domains (space separated)", max_length=1024, default="", blank=True)
  include_domains       = models.CharField("Include Domains (space separated)", max_length=1024, default="", blank=True)
  
  
  class Meta:
    verbose_name        = "Website"
    verbose_name_plural = "Websites"
    ordering = ['url']

  def __unicode__(self):
      return self.title + ": " + self.url  
      
