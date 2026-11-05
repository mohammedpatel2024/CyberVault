from django.db import models

class WebsiteScan(models.Model):
    url = models.URLField(max_length=2048)
    domain = models.CharField(max_length=253)
    ip_addresses = models.JSONField(default=list)
    dns_records = models.JSONField(default=dict)
    tls_status = models.CharField(max_length=50, default="Not checked")
    tls_details = models.JSONField(default=dict)
    url_features = models.JSONField(default=dict)
    phishing_probability = models.FloatField(null=True, blank=True)
    model_status = models.CharField(max_length=255, blank=True)
    model_version = models.CharField(max_length=100, blank=True)
    reputation_status = models.CharField(max_length=50, default="Not checked")
    reputation_details = models.JSONField(default=dict)
    risk_score = models.PositiveSmallIntegerField(default=0)
    risk_level = models.CharField(max_length=50, default="Incomplete assessment")
    explanations = models.JSONField(default=list)
    scanned_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        ordering = ["-scanned_at", "-pk"]
    def __str__(self):
        return self.domain
