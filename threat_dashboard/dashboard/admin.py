from django.contrib import admin
from .models import ThreatLog, SearchHistory, ThreatStatistics

@admin.register(ThreatLog)
class ThreatLogAdmin(admin.ModelAdmin):
    list_display = ['threat_type', 'target', 'severity', 'detected_at', 'is_active']
    list_filter = ['threat_type', 'severity', 'is_active']
    search_fields = ['target', 'description']

@admin.register(SearchHistory)
class SearchHistoryAdmin(admin.ModelAdmin):
    list_display = ['user', 'search_type', 'query', 'searched_at']
    list_filter = ['search_type', 'threat_detected']

@admin.register(ThreatStatistics)
class ThreatStatisticsAdmin(admin.ModelAdmin):
    list_display = ['date', 'total_threats', 'malware_count', 'phishing_count']
    ordering = ['-date']