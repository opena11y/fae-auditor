from django.contrib import admin
from audits.models import Audit
from audits.models import AuditGroup
from audits.models import AuditGroupItem
from audits.models import AuditGroup2
from audits.models import AuditGroup2Item
from audits.models import Website

class AuditAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'depth', 'ruleset', 'user')
    list_filter = ('user',)
    
admin.site.register(Audit, AuditAdmin)

class AuditGroupAdmin(admin.ModelAdmin):
    list_display = ('title', 'audit', 'slug', 'position')
    list_filter = ('audit',)
    
admin.site.register(AuditGroup, AuditGroupAdmin)

class AuditGroupItemAdmin(admin.ModelAdmin):
    list_display = ('title', 'group', 'slug')
    list_filter = ('group',)
    
admin.site.register(AuditGroupItem, AuditGroupItemAdmin)

class AuditGroup2Admin(admin.ModelAdmin):
    list_display = ('title', 'audit', 'slug', 'position')
    list_filter = ('audit',)
    
admin.site.register(AuditGroup2, AuditGroup2Admin)

class AuditGroup2ItemAdmin(admin.ModelAdmin):
    list_display = ('title', 'group2', 'group_item', 'slug')
    list_filter = ('group2', 'group_item')
    
admin.site.register(AuditGroup2Item, AuditGroup2ItemAdmin)

class WebsiteAdmin(admin.ModelAdmin):
    list_display = ('url', 'title', 'audit', 'group_item', 'group2_item')
    list_filter = ('audit', 'group_item', 'group2_item')

admin.site.register(Website, WebsiteAdmin)

