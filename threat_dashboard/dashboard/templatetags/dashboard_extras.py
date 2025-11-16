from django import template

register = template.Library()

@register.filter
def get_type_color(threat_type):
    """Return Bootstrap color class for threat type"""
    colors = {
        'malware': 'danger',
        'phishing': 'warning',
        'botnet': 'info',
        'ransomware': 'danger',
        'exploit': 'primary',
    }
    return colors.get(threat_type, 'secondary')