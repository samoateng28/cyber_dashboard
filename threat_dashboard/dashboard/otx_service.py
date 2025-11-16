from OTXv2 import OTXv2, IndicatorTypes
import os
from django.conf import settings
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

class OTXService:
    """Service class for interacting with AlienVault OTX API"""
    
    def __init__(self):
        api_key = getattr(settings, 'OTX_API_KEY', '') or os.environ.get('OTX_API_KEY', '')
        if not api_key:
            raise ValueError("OTX_API_KEY not configured. Please set it in settings or environment variables.")
        self.otx = OTXv2(api_key)
    
    def lookup_ip(self, ip_address):
        """
        Look up an IP address in OTX
        
        Returns:
            dict: Contains threat information, pulses, and reputation data
        """
        try:
            # Log the endpoint being called
            endpoint_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            logger.info(f"[OTX API] Calling endpoint: {endpoint_url}")
            logger.info(f"[OTX API] IP Address: {ip_address}")
            
            # Use IndicatorTypes.IPv4 instead of string "IPv4"
            full_data = self.otx.get_indicator_details_by_section(
                indicator_type=IndicatorTypes.IPv4,  # Changed from "IPv4" string
                indicator=ip_address,
                section="general"
            )
            
            # Log the raw response
            logger.info(f"[OTX API] Response type: {type(full_data)}")
            logger.info(f"[OTX API] Response content: {json.dumps(full_data, indent=2, default=str)}")
            
            # Check if we got a valid response
            if not isinstance(full_data, dict):
                logger.error(f"[OTX API] ERROR: Non-dict response for IP {ip_address}")
                logger.error(f"[OTX API] Response type: {type(full_data)}, Value: {full_data}")
                return {
                    'ip': ip_address,
                    'found': False,
                    'error': True,
                    'is_malicious': False,
                }
            
            # Log successful response structure
            logger.info(f"[OTX API] Successfully received dict response")
            logger.info(f"[OTX API] Response keys: {list(full_data.keys())}")
            
            # Extract pulse_info (nested object with count and pulses array)
            pulse_info = full_data.get('pulse_info', {})
            if not isinstance(pulse_info, dict):
                logger.warning(f"[OTX API] pulse_info is not a dict: {type(pulse_info)}")
                pulse_info = {}
            
            pulse_list = pulse_info.get('pulses', [])
            pulse_count = pulse_info.get('count', 0)
            
            logger.info(f"[OTX API] Pulse count: {pulse_count}")
            logger.info(f"[OTX API] Number of pulses: {len(pulse_list)}")
            
            # Extract geo data (at root level in the response)
            geo_data = {
                'country_name': full_data.get('country_name'),
                'country_code': full_data.get('country_code'),
                'city': full_data.get('city'),
                'region': full_data.get('region'),
                'subdivision': full_data.get('subdivision'),
                'latitude': full_data.get('latitude'),
                'longitude': full_data.get('longitude'),
                'postal_code': full_data.get('postal_code'),
                'asn': full_data.get('asn'),
            }
            
            logger.info(f"[OTX API] Geo data: {json.dumps(geo_data, indent=2, default=str)}")
            
            # Extract reputation (it's a number, not a dict)
            reputation_value = full_data.get('reputation', 0)
            logger.info(f"[OTX API] Reputation: {reputation_value}")
            
            # Get passive DNS separately - also use IndicatorTypes.IPv4
            passive_dns_data = {}
            try:
                logger.info(f"[OTX API] Fetching passive_dns for IP {ip_address}")
                passive_dns_data = self.otx.get_indicator_details_by_section(
                    indicator_type=IndicatorTypes.IPv4,  # Changed from "IPv4" string
                    indicator=ip_address,
                    section="passive_dns"
                )
                logger.info(f"[OTX API] Passive DNS response: {json.dumps(passive_dns_data, indent=2, default=str)}")
            except Exception as e:
                logger.warning(f"[OTX API] Could not get passive_dns for IP {ip_address}: {str(e)}")
                logger.warning(f"[OTX API] Passive DNS error type: {type(e).__name__}")
                passive_dns_data = {}
            
            # Extract passive DNS list
            passive_dns_list = []
            if isinstance(passive_dns_data, dict):
                passive_dns_list = passive_dns_data.get('passive_dns', [])
            
            # Build the response
            result = {
                'ip': ip_address,
                'found': True,  # API call succeeded
                'general': {
                    'indicator': full_data.get('indicator'),
                    'type': full_data.get('type'),
                    'asn': full_data.get('asn'),
                    'whois': full_data.get('whois'),
                },
                'pulses': pulse_list if isinstance(pulse_list, list) else [],
                'pulse_count': int(pulse_count) if isinstance(pulse_count, (int, float)) else 0,
                'reputation': reputation_value,
                'geo': geo_data,
                'passive_dns': passive_dns_list if isinstance(passive_dns_list, list) else [],
                'is_malicious': pulse_count > 0,
                'last_seen': self._get_last_seen(pulse_list),
            }
            
            logger.info(f"[OTX API] Final result: {json.dumps(result, indent=2, default=str)}")
            return result
            
        except AttributeError as e:
            # Handle the 'str' object has no attribute 'api_support' error
            logger.error(f"[OTX API] AttributeError for IP {ip_address}: {str(e)}")
            logger.error(f"[OTX API] Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"[OTX API] Traceback: {traceback.format_exc()}")
            return {
                'ip': ip_address,
                'found': False,
                'error': True,
                'is_malicious': False,
            }
        except Exception as e:
            logger.error(f"[OTX API] Exception for IP {ip_address}: {str(e)}")
            logger.error(f"[OTX API] Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"[OTX API] Traceback: {traceback.format_exc()}")
            return {
                'ip': ip_address,
                'found': False,
                'error': True,
                'is_malicious': False,
            }
    
    def _get_last_seen(self, pulses):
        """Extract the most recent pulse date"""
        if not pulses or not isinstance(pulses, list):
            return None
        try:
            dates = []
            for p in pulses:
                if isinstance(p, dict):
                    # Try different date fields
                    date_str = p.get('modified') or p.get('created') or p.get('updated')
                    if date_str:
                        dates.append(date_str)
            if dates:
                return max(dates)
        except:
            pass
        return None