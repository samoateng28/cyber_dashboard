from faker import Faker
import random
from datetime import datetime, timedelta
from .models import ThreatLog, ThreatStatistics

fake = Faker()

def generate_fake_threats(count=50):
    """Generate fake threat logs for testing"""
    threat_types = ['malware', 'phishing', 'botnet', 'ransomware', 'exploit']
    severity_levels = ['critical', 'high', 'medium', 'low']
    
    threats = []
    for _ in range(count):
        threat_type = random.choice(threat_types)
        
        # Generate appropriate target based on threat type
        if random.choice([True, False]):
            target = fake.ipv4()
        else:
            target = fake.domain_name()
        
        severity = random.choice(severity_levels)
        
        descriptions = {
            'malware': f"Malicious software detected attempting to compromise system security at {target}",
            'phishing': f"Phishing attempt detected from {target} trying to steal credentials",
            'botnet': f"Botnet activity identified from {target} participating in DDoS attacks",
            'ransomware': f"Ransomware signature detected from {target} attempting file encryption",
            'exploit': f"Exploitation attempt detected from {target} targeting known vulnerabilities"
        }
        
        threat = ThreatLog(
            threat_type=threat_type,
            target=target,
            severity=severity,
            description=descriptions[threat_type],
            source='AlienVault OTX',
            is_active=random.choice([True, True, True, False])  # 75% active
        )
        threats.append(threat)
    
    # Bulk create
    ThreatLog.objects.bulk_create(threats)
    return len(threats)


def generate_fake_statistics(days=30):
    """Generate fake statistics for the last N days"""
    for i in range(days):
        date = datetime.now().date() - timedelta(days=i)
        
        # Check if stats already exist for this date
        if ThreatStatistics.objects.filter(date=date).exists():
            continue
        
        malware = random.randint(10, 50)
        phishing = random.randint(5, 30)
        botnet = random.randint(3, 20)
        ransomware = random.randint(2, 15)
        exploit = random.randint(5, 25)
        
        ThreatStatistics.objects.create(
            date=date,
            total_threats=malware + phishing + botnet + ransomware + exploit,
            malware_count=malware,
            phishing_count=phishing,
            botnet_count=botnet,
            ransomware_count=ransomware,
            exploit_count=exploit
        )
    
    return days


def get_dashboard_stats():
    """Get aggregated statistics for dashboard"""
    from django.db.models import Count, Q
    from datetime import datetime, timedelta
    
    # Get counts
    total_threats = ThreatLog.objects.count()
    active_threats = ThreatLog.objects.filter(is_active=True).count()
    
    # Count by type
    malware_count = ThreatLog.objects.filter(threat_type='malware').count()
    phishing_count = ThreatLog.objects.filter(threat_type='phishing').count()
    
    # Count malicious IPs (targets that are IP addresses)
    import re
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    all_threats = ThreatLog.objects.all()
    malicious_ips = len([t for t in all_threats if ip_pattern.match(t.target)])
    
    # Count domains
    blocked_domains = len([t for t in all_threats if not ip_pattern.match(t.target)])
    
    # Today's scans
    today = datetime.now().date()
    scans_today = ThreatLog.objects.filter(detected_at__date=today).count()
    
    return {
        'total_threats': total_threats,
        'active_threats': active_threats,
        'malicious_ips': malicious_ips,
        'blocked_domains': blocked_domains,
        'scans_today': scans_today,
        'malware_count': malware_count,
        'phishing_count': phishing_count,
    }