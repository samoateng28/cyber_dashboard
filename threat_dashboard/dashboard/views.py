from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import models
from .forms import LoginForm
from .models import ThreatLog, ThreatStatistics
from .utils import get_dashboard_stats
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from .otx_service import OTXService
from .models import SearchHistory
import re
import logging
from .abuseipdb_service import AbuseIPDBService

logger = logging.getLogger(__name__)


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    
    return render(request, 'dashboard/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')

@login_required
def unified_search_view(request):
    """Unified search that detects IP or domain and redirects accordingly"""
    if request.method == 'POST':
        query = request.POST.get('search_query', '').strip().lower()
        
        if not query:
            messages.warning(request, 'Please enter an IP address or domain to search.')
            return redirect('dashboard')
        
        # IP address pattern (IPv4)
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        # Domain pattern (no scheme, no path)
        domain_pattern = re.compile(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$')
        
        # Check if it's an IP address
        if ip_pattern.match(query):
            # Redirect to IP lookup with the query as POST data
            request.session['ip_lookup_query'] = query
            return redirect('ip_lookup')
        
        # Check if it's a domain
        elif domain_pattern.match(query):
            # Redirect to domain lookup with the query as POST data
            request.session['domain_lookup_query'] = query
            return redirect('domain_lookup')
        
        else:
            messages.error(request, 'Invalid input. Please enter a valid IP address (e.g., 192.168.1.1) or domain (e.g., example.com).')
            return redirect('dashboard')
    
    return redirect('dashboard')

@login_required
def dashboard_view(request):
    # Get dashboard statistics
    stats = get_dashboard_stats()
    
    # Get recent threats (last 10)
    recent_threats = ThreatLog.objects.all()[:10]
    
    # Get threat distribution data for charts
    threat_types = ThreatLog.objects.values('threat_type').annotate(
        count=models.Count('threat_type')
    )
    
    # Get severity distribution
    severity_dist = ThreatLog.objects.values('severity').annotate(
        count=models.Count('severity')
    )
    
    # Get last 7 days statistics for trend chart
    last_7_days = []
    for i in range(6, -1, -1):
        date = datetime.now().date() - timedelta(days=i)
        day_stats = ThreatStatistics.objects.filter(date=date).first()
        last_7_days.append({
            'date': date.strftime('%b %d'),
            'count': day_stats.total_threats if day_stats else 0
        })
    
    # Process data with pandas
    df_threats = pd.DataFrame(list(threat_types))
    df_severity = pd.DataFrame(list(severity_dist))
    
    # Prepare chart data
    chart_data = {
        'threat_types': list(df_threats.to_dict('records')) if not df_threats.empty else [],
        'severity': list(df_severity.to_dict('records')) if not df_severity.empty else [],
        'trend': last_7_days
    }
    
    context = {
        'user': request.user,
        'stats': stats,
        'recent_threats': recent_threats,
        'chart_data': chart_data,
    }
    return render(request, 'dashboard/dashboard.html', context)

@login_required
def domain_lookup_view(request):
    """View for domain lookup using OTX API"""
    context = {
        'user': request.user,
        'domain': '',
        'result': None,
        'has_error': False,
    }

    # Check if there's a query from unified search
    if 'domain_lookup_query' in request.session:
        domain = request.session.pop('domain_lookup_query')
        # Process the domain lookup
        try:
            otx_service = OTXService()
            result = otx_service.lookup_domain(domain)

            if not result.get('error', False):
                # Save search history
                SearchHistory.objects.create(
                    user=request.user,
                    search_type='domain',
                    query=domain,
                    result_found=result.get('found', False),
                    threat_detected=result.get('is_malicious', False)
                )

                # If malicious, log as a threat
                if result.get('is_malicious', False):
                    pulse_count = result.get('pulse_count', 0)
                    ThreatLog.objects.create(
                        threat_type='phishing',
                        target=domain,
                        severity='high' if pulse_count > 5 else 'medium',
                        description=f"Malicious domain detected via OTX. Found in {pulse_count} pulse(s).",
                        source='AlienVault OTX',
                        is_active=True
                    )

                context['result'] = result
                messages.success(request, f'Successfully analyzed domain: {domain}')
            else:
                messages.error(request, 'Unable to retrieve threat intelligence data for this domain. Please try again later.')
                context['has_error'] = True
                context['domain'] = domain

        except ValueError:
            messages.error(request, 'Service configuration error. Please contact support.')
            context['has_error'] = True
        except Exception:
            messages.error(request, 'Unable to connect to threat intelligence service. Please check your internet connection and try again.')
            context['has_error'] = True
            context['domain'] = domain

    elif request.method == 'POST':
        domain = request.POST.get('domain', '').strip().lower()

        # Simple domain validation
        domain_pattern = re.compile(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$')

        if not domain:
            messages.error(request, 'Please enter a domain to search (e.g., example.com).')
            context['has_error'] = True
        elif not domain_pattern.match(domain):
            messages.error(request, 'Invalid domain format. Please enter a valid domain (e.g., example.com).')
            context['has_error'] = True
        else:
            try:
                otx_service = OTXService()
                result = otx_service.lookup_domain(domain)

                if not result.get('error', False):
                    # Save search history
                    SearchHistory.objects.create(
                        user=request.user,
                        search_type='domain',
                        query=domain,
                        result_found=result.get('found', False),
                        threat_detected=result.get('is_malicious', False)
                    )

                    # If malicious, log as a threat
                    if result.get('is_malicious', False):
                        pulse_count = result.get('pulse_count', 0)
                        ThreatLog.objects.create(
                            threat_type='phishing',
                            target=domain,
                            severity='high' if pulse_count > 5 else 'medium',
                            description=f"Malicious domain detected via OTX. Found in {pulse_count} pulse(s).",
                            source='AlienVault OTX',
                            is_active=True
                        )

                    context['result'] = result
                    messages.success(request, f'Successfully analyzed domain: {domain}')
                else:
                    messages.error(request, 'Unable to retrieve threat intelligence data for this domain. Please try again later.')
                    context['has_error'] = True
                    context['domain'] = domain

            except ValueError:
                messages.error(request, 'Service configuration error. Please contact support.')
                context['has_error'] = True
            except Exception:
                messages.error(request, 'Unable to connect to threat intelligence service. Please check your internet connection and try again.')
                context['has_error'] = True
                context['domain'] = domain

    # Recent domain searches
    recent_searches = SearchHistory.objects.filter(
        user=request.user,
        search_type='domain'
    ).order_by('-searched_at')[:10]

    context['recent_searches'] = recent_searches

    return render(request, 'dashboard/domain_lookup.html', context)

@login_required
def ip_lookup_view(request):
    """View for IP address lookup using OTX API"""
    context = {
        'user': request.user,
        'ip_address': '',
        'result': None,
        'error': None,
        'has_error': False,
    }
    
    # Check if there's a query from unified search
    if 'ip_lookup_query' in request.session:
        ip_address = request.session.pop('ip_lookup_query')
        # Process the IP lookup
        try:
            # Initialize services
            otx_service = OTXService()
            
            # Perform OTX lookup
            result = otx_service.lookup_ip(ip_address)
            
            # Perform AbuseIPDB lookup
            abuse_result = None
            try:
                abuseipdb_service = AbuseIPDBService()
                abuse_result = abuseipdb_service.lookup_ip(ip_address)
                
                # Merge AbuseIPDB data into result
                if not abuse_result.get('error', False):
                    result['abuseipdb'] = abuse_result
                    # Update is_malicious if AbuseIPDB also flags it
                    if abuse_result.get('is_abusive', False):
                        result['is_malicious'] = True
                else:
                    result['abuseipdb'] = None
            except (ValueError, Exception) as abuse_error:
                logger.warning(f"AbuseIPDB lookup failed for {ip_address}: {str(abuse_error)}")
                result['abuseipdb'] = None
            
            # Only save search history if API call succeeded
            if not result.get('error', False):
                # Determine if threat detected
                threat_detected = result.get('is_malicious', False) or (
                    result.get('abuseipdb') and result['abuseipdb'].get('is_abusive', False)
                )
                
                # Save search history
                SearchHistory.objects.create(
                    user=request.user,
                    search_type='ip',
                    query=ip_address,
                    result_found=result.get('found', False),
                    threat_detected=threat_detected
                )
                
                # If malicious, create a ThreatLog entry
                if threat_detected:
                    pulse_count = result.get('pulse_count', 0)
                    abuse_score = result.get('abuseipdb', {}).get('abuse_confidence_score', 0) if result.get('abuseipdb') else 0
                    
                    description_parts = []
                    if pulse_count > 0:
                        description_parts.append(f"Found in {pulse_count} OTX threat intelligence pulse(s)")
                    if abuse_score > 0:
                        description_parts.append(f"AbuseIPDB confidence score: {abuse_score}%")
                    
                    description = f"Malicious IP detected. {' | '.join(description_parts)}."
                    
                    ThreatLog.objects.create(
                        threat_type='malware',
                        target=ip_address,
                        severity='high' if (pulse_count > 5 or abuse_score > 75) else 'medium',
                        description=description,
                        source='AlienVault OTX & AbuseIPDB',
                        is_active=True
                    )
                
                context['result'] = result
                messages.success(request, f'Successfully analyzed IP address: {ip_address}')
            else:
                messages.error(request, 'Unable to retrieve threat intelligence data. Please check your connection and try again.')
                context['has_error'] = True
                context['ip_address'] = ip_address
                
        except ValueError:
            messages.error(request, 'Service configuration error. Please contact support.')
            context['has_error'] = True
        except Exception:
            messages.error(request, 'Unable to connect to threat intelligence service. Please check your internet connection and try again.')
            context['has_error'] = True
            context['ip_address'] = ip_address
    
    elif request.method == 'POST':
        ip_address = request.POST.get('ip_address', '').strip()
        
        # Validate IP address format
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        if not ip_address:
            messages.error(request, 'Please enter an IP address to search.')
            context['has_error'] = True
        elif not ip_pattern.match(ip_address):
            messages.error(request, 'Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.1).')
            context['has_error'] = True
        else:
            try:
                # Initialize services
                otx_service = OTXService()
                
                # Perform OTX lookup
                result = otx_service.lookup_ip(ip_address)
                
                # Perform AbuseIPDB lookup
                abuse_result = None
                try:
                    abuseipdb_service = AbuseIPDBService()
                    abuse_result = abuseipdb_service.lookup_ip(ip_address)
                    
                    # Merge AbuseIPDB data into result
                    if not abuse_result.get('error', False):
                        result['abuseipdb'] = abuse_result
                        # Update is_malicious if AbuseIPDB also flags it
                        if abuse_result.get('is_abusive', False):
                            result['is_malicious'] = True
                    else:
                        result['abuseipdb'] = None
                except (ValueError, Exception) as abuse_error:
                    logger.warning(f"AbuseIPDB lookup failed for {ip_address}: {str(abuse_error)}")
                    result['abuseipdb'] = None
                
                # Only save search history if API call succeeded
                if not result.get('error', False):
                    # Determine if threat detected
                    threat_detected = result.get('is_malicious', False) or (
                        result.get('abuseipdb') and result['abuseipdb'].get('is_abusive', False)
                    )
                    
                    # Save search history
                    SearchHistory.objects.create(
                        user=request.user,
                        search_type='ip',
                        query=ip_address,
                        result_found=result.get('found', False),
                        threat_detected=threat_detected
                    )
                    
                    # If malicious, create a ThreatLog entry
                    if threat_detected:
                        pulse_count = result.get('pulse_count', 0)
                        abuse_score = result.get('abuseipdb', {}).get('abuse_confidence_score', 0) if result.get('abuseipdb') else 0
                        
                        description_parts = []
                        if pulse_count > 0:
                            description_parts.append(f"Found in {pulse_count} OTX threat intelligence pulse(s)")
                        if abuse_score > 0:
                            description_parts.append(f"AbuseIPDB confidence score: {abuse_score}%")
                        
                        description = f"Malicious IP detected. {' | '.join(description_parts)}."
                        
                        ThreatLog.objects.create(
                            threat_type='malware',
                            target=ip_address,
                            severity='high' if (pulse_count > 5 or abuse_score > 75) else 'medium',
                            description=description,
                            source='AlienVault OTX & AbuseIPDB',
                            is_active=True
                        )
                    
                    context['result'] = result
                    messages.success(request, f'Successfully analyzed IP address: {ip_address}')
                else:
                    messages.error(request, 'Unable to retrieve threat intelligence data. Please check your connection and try again.')
                    context['has_error'] = True
                    context['ip_address'] = ip_address
                    
            except ValueError:
                messages.error(request, 'Service configuration error. Please contact support.')
                context['has_error'] = True
            except Exception:
                messages.error(request, 'Unable to connect to threat intelligence service. Please check your internet connection and try again.')
                context['has_error'] = True
                context['ip_address'] = ip_address
    
    # Get recent search history for this user
    recent_searches = SearchHistory.objects.filter(
        user=request.user,
        search_type='ip'
    ).order_by('-searched_at')[:10]
    
    context['recent_searches'] = recent_searches
    
    return render(request, 'dashboard/ip_lookup.html', context)