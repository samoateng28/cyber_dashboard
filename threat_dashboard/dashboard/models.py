from django.db import models
from django.contrib.auth.models import User


class ThreatLog(models.Model):
    THREAT_TYPES = [
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('botnet', 'Botnet'),
        ('ransomware', 'Ransomware'),
        ('exploit', 'Exploit'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    threat_type = models.CharField(max_length=50, choices=THREAT_TYPES)
    target = models.CharField(max_length=255)  # IP, domain, or hash
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS)
    description = models.TextField()
    source = models.CharField(max_length=100, default='AlienVault OTX')
    detected_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.threat_type} - {self.target}"


class SearchHistory(models.Model):
    SEARCH_TYPES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('hash', 'File Hash'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    search_type = models.CharField(max_length=20, choices=SEARCH_TYPES)
    query = models.CharField(max_length=255)
    result_found = models.BooleanField(default=False)
    threat_detected = models.BooleanField(default=False)
    searched_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-searched_at']
        verbose_name_plural = 'Search Histories'
    
    def __str__(self):
        return f"{self.user.username} - {self.search_type} - {self.query}"


class ThreatStatistics(models.Model):
    date = models.DateField(unique=True)
    total_threats = models.IntegerField(default=0)
    malware_count = models.IntegerField(default=0)
    phishing_count = models.IntegerField(default=0)
    botnet_count = models.IntegerField(default=0)
    ransomware_count = models.IntegerField(default=0)
    exploit_count = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-date']
        verbose_name_plural = 'Threat Statistics'
    
    def __str__(self):
        return f"Stats for {self.date}"