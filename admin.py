from django.contrib import admin
from .models import WebsiteScan
@admin.register(WebsiteScan)
class WebsiteScanAdmin(admin.ModelAdmin):
    list_display = ("domain", "risk_level", "risk_score", "phishing_probability", "tls_status", "scanned_at")
    list_filter = ("risk_level", "tls_status", "reputation_status")
    search_fields = ("url", "domain")
    readonly_fields = tuple(field.name for field in WebsiteScan._meta.fields)
