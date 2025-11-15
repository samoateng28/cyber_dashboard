import requests
import os
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class AbuseIPDBService:
    """Service class for interacting with AbuseIPDB API"""
    
    def __init__(self):
        api_key = getattr(settings, 'ABUSEIPDB_API_KEY', '') or os.environ.get('ABUSEIPDB_API_KEY', '')
        if not api_key:
            raise ValueError("ABUSEIPDB_API_KEY not configured. Please set it in settings or environment variables.")
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    def lookup_ip(self, ip_address, max_age_days=90):
        """
        Look up an IP address in AbuseIPDB
        
        Args:
            ip_address: IP address to check
            max_age_days: Maximum age of reports in days (default 90)
        
        Returns:
            dict: Contains abuse information, confidence score, and reports
        """
        try:
            endpoint = f"{self.base_url}/check"
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': max_age_days,
                'verbose': ''  # Get additional details
            }
            
            logger.info(f"[AbuseIPDB] Checking IP: {ip_address}")
            
            response = requests.get(endpoint, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    abuse_data = data['data']
                    
                    result = {
                        'ip': ip_address,
                        'found': True,
                        'abuse_confidence_score': abuse_data.get('abuseConfidenceScore', 0),
                        'is_public': abuse_data.get('isPublic', False),
                        'ip_version': abuse_data.get('ipVersion', 4),
                        'is_whitelisted': abuse_data.get('isWhitelisted', False),
                        'usage_type': abuse_data.get('usageType', 'Unknown'),
                        'isp': abuse_data.get('isp', 'Unknown'),
                        'domain': abuse_data.get('domain', ''),
                        'hostnames': abuse_data.get('hostnames', []),
                        'country_code': abuse_data.get('countryCode', ''),
                        'total_reports': abuse_data.get('totalReports', 0),
                        'num_distinct_users': abuse_data.get('numDistinctUsers', 0),
                        'last_reported_at': abuse_data.get('lastReportedAt', ''),
                        'is_abusive': abuse_data.get('abuseConfidenceScore', 0) > 0,
                    }
                    
                    logger.info(f"[AbuseIPDB] Successfully retrieved data for {ip_address}")
                    logger.info(f"[AbuseIPDB] Abuse Confidence Score: {result['abuse_confidence_score']}")
                    logger.info(f"[AbuseIPDB] Total Reports: {result['total_reports']}")
                    
                    return result
                else:
                    logger.warning(f"[AbuseIPDB] No data in response for {ip_address}")
                    return {
                        'ip': ip_address,
                        'found': False,
                        'error': True,
                        'is_abusive': False,
                    }
            else:
                logger.error(f"[AbuseIPDB] API error for {ip_address}: Status {response.status_code}")
                logger.error(f"[AbuseIPDB] Response: {response.text}")
                return {
                    'ip': ip_address,
                    'found': False,
                    'error': True,
                    'is_abusive': False,
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"[AbuseIPDB] Request exception for {ip_address}: {str(e)}")
            return {
                'ip': ip_address,
                'found': False,
                'error': True,
                'is_abusive': False,
            }
        except Exception as e:
            logger.error(f"[AbuseIPDB] Exception for {ip_address}: {str(e)}")
            return {
                'ip': ip_address,
                'found': False,
                'error': True,
                'is_abusive': False,
            }