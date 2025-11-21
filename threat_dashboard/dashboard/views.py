from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import models
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from .forms import LoginForm
from .models import ThreatLog, ThreatStatistics, SearchHistory
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from .otx_service import OTXService
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
        
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        domain_pattern = re.compile(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$')
        
        if ip_pattern.match(query):
            request.session['ip_lookup_query'] = query
            return redirect('ip_lookup')
        elif domain_pattern.match(query):
            request.session['domain_lookup_query'] = query
            return redirect('domain_lookup')
        else:
            messages.error(request, 'Invalid input. Please enter a valid IP address or domain.')
            return redirect('dashboard')
    
    return redirect('dashboard')


def get_real_dashboard_stats():
    """Calculate real statistics from the database"""
    today = timezone.now().date()
    
    # Total active threats
    total_threats = ThreatLog.objects.filter(is_active=True).count()
    
    # Malicious IPs (threats with IP-like targets that are malware type)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    malicious_ips = ThreatLog.objects.filter(
        is_active=True,
        threat_type='malware'
    ).filter(target__regex=ip_pattern).count()
    
    # Blocked domains (phishing threats)
    blocked_domains = ThreatLog.objects.filter(
        is_active=True,
        threat_type='phishing'
    ).count()
    
    # Scans today (searches performed today)
    scans_today = SearchHistory.objects.filter(
        searched_at__date=today
    ).count()
    
    return {
        'total_threats': total_threats,
        'malicious_ips': malicious_ips,
        'blocked_domains': blocked_domains,
        'scans_today': scans_today,
    }


@login_required
def dashboard_view(request):
    # Get real dashboard statistics
    stats = get_real_dashboard_stats()
    
    # Get recent threats (last 10)
    recent_threats = ThreatLog.objects.all()[:10]
    
    # Get threat distribution by type
    threat_types = list(ThreatLog.objects.values('threat_type').annotate(
        count=Count('threat_type')
    ).order_by('-count'))
    
    # Get severity distribution
    severity_dist = list(ThreatLog.objects.values('severity').annotate(
        count=Count('severity')
    ).order_by('-count'))
    
    # Get last 7 days trend data from actual ThreatLog entries
    last_7_days = []
    for i in range(6, -1, -1):
        date = timezone.now().date() - timedelta(days=i)
        
        # Count threats detected on this day
        day_count = ThreatLog.objects.filter(
            detected_at__date=date
        ).count()
        
        # Also check ThreatStatistics if available
        day_stats = ThreatStatistics.objects.filter(date=date).first()
        if day_stats and day_stats.total_threats > day_count:
            day_count = day_stats.total_threats
        
        last_7_days.append({
            'date': date.strftime('%b %d'),
            'count': day_count
        })
    
    # Prepare chart data
    chart_data = {
        'threat_types': threat_types if threat_types else [],
        'severity': severity_dist if severity_dist else [],
        'trend': last_7_days
    }
    
    # Get additional analytics
    analytics = get_threat_analytics()
    
    context = {
        'user': request.user,
        'stats': stats,
        'recent_threats': recent_threats,
        'chart_data': chart_data,
        'analytics': analytics,
    }
    return render(request, 'dashboard/dashboard.html', context)


def get_threat_analytics():
    """Get additional analytics for the dashboard"""
    today = timezone.now().date()
    yesterday = today - timedelta(days=1)
    last_week = today - timedelta(days=7)
    
    # Threats today vs yesterday
    threats_today = ThreatLog.objects.filter(detected_at__date=today).count()
    threats_yesterday = ThreatLog.objects.filter(detected_at__date=yesterday).count()
    
    # Calculate percentage change
    if threats_yesterday > 0:
        change_pct = ((threats_today - threats_yesterday) / threats_yesterday) * 100
    else:
        change_pct = 100 if threats_today > 0 else 0
    
    # Most common threat type this week
    common_threat = ThreatLog.objects.filter(
        detected_at__date__gte=last_week
    ).values('threat_type').annotate(
        count=Count('threat_type')
    ).order_by('-count').first()
    
    # Critical/High severity count
    critical_high = ThreatLog.objects.filter(
        is_active=True,
        severity__in=['critical', 'high']
    ).count()
    
    # Recent search activity
    recent_searches = SearchHistory.objects.filter(
        searched_at__date__gte=last_week
    ).count()
    
    # Threat detection rate (searches that found threats)
    total_searches = SearchHistory.objects.filter(
        searched_at__date__gte=last_week
    ).count()
    threat_searches = SearchHistory.objects.filter(
        searched_at__date__gte=last_week,
        threat_detected=True
    ).count()
    
    detection_rate = (threat_searches / total_searches * 100) if total_searches > 0 else 0
    
    return {
        'threats_today': threats_today,
        'threats_yesterday': threats_yesterday,
        'change_percentage': round(change_pct, 1),
        'change_direction': 'up' if change_pct > 0 else 'down' if change_pct < 0 else 'same',
        'most_common_threat': common_threat['threat_type'] if common_threat else None,
        'critical_high_count': critical_high,
        'weekly_searches': recent_searches,
        'detection_rate': round(detection_rate, 1),
    }


@login_required
def domain_lookup_view(request):
    """View for domain lookup using OTX API"""
    context = {
        'user': request.user,
        'domain': '',
        'result': None,
        'has_error': False,
    }

    if 'domain_lookup_query' in request.session:
        domain = request.session.pop('domain_lookup_query')
        try:
            otx_service = OTXService()
            result = otx_service.lookup_domain(domain)

            if not result.get('error', False):
                SearchHistory.objects.create(
                    user=request.user,
                    search_type='domain',
                    query=domain,
                    result_found=result.get('found', False),
                    threat_detected=result.get('is_malicious', False)
                )

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
                messages.error(request, 'Unable to retrieve threat intelligence data.')
                context['has_error'] = True
                context['domain'] = domain

        except ValueError:
            messages.error(request, 'Service configuration error.')
            context['has_error'] = True
        except Exception:
            messages.error(request, 'Unable to connect to threat intelligence service.')
            context['has_error'] = True
            context['domain'] = domain

    elif request.method == 'POST':
        domain = request.POST.get('domain', '').strip().lower()
        domain_pattern = re.compile(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$')

        if not domain:
            messages.error(request, 'Please enter a domain to search.')
            context['has_error'] = True
        elif not domain_pattern.match(domain):
            messages.error(request, 'Invalid domain format.')
            context['has_error'] = True
        else:
            try:
                otx_service = OTXService()
                result = otx_service.lookup_domain(domain)

                if not result.get('error', False):
                    SearchHistory.objects.create(
                        user=request.user,
                        search_type='domain',
                        query=domain,
                        result_found=result.get('found', False),
                        threat_detected=result.get('is_malicious', False)
                    )

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
                    messages.error(request, 'Unable to retrieve threat intelligence data.')
                    context['has_error'] = True
                    context['domain'] = domain

            except ValueError:
                messages.error(request, 'Service configuration error.')
                context['has_error'] = True
            except Exception:
                messages.error(request, 'Unable to connect to threat intelligence service.')
                context['has_error'] = True
                context['domain'] = domain

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
    
    if 'ip_lookup_query' in request.session:
        ip_address = request.session.pop('ip_lookup_query')
        try:
            otx_service = OTXService()
            result = otx_service.lookup_ip(ip_address)
            
            abuse_result = None
            try:
                abuseipdb_service = AbuseIPDBService()
                abuse_result = abuseipdb_service.lookup_ip(ip_address)
                
                if not abuse_result.get('error', False):
                    result['abuseipdb'] = abuse_result
                    if abuse_result.get('is_abusive', False):
                        result['is_malicious'] = True
                else:
                    result['abuseipdb'] = None
            except (ValueError, Exception) as e:
                logger.warning(f"AbuseIPDB lookup failed: {str(e)}")
                result['abuseipdb'] = None
            
            if not result.get('error', False):
                threat_detected = result.get('is_malicious', False) or (
                    result.get('abuseipdb') and result['abuseipdb'].get('is_abusive', False)
                )
                
                SearchHistory.objects.create(
                    user=request.user,
                    search_type='ip',
                    query=ip_address,
                    result_found=result.get('found', False),
                    threat_detected=threat_detected
                )
                
                if threat_detected:
                    pulse_count = result.get('pulse_count', 0)
                    abuse_score = result.get('abuseipdb', {}).get('abuse_confidence_score', 0) if result.get('abuseipdb') else 0
                    
                    desc_parts = []
                    if pulse_count > 0:
                        desc_parts.append(f"Found in {pulse_count} OTX pulse(s)")
                    if abuse_score > 0:
                        desc_parts.append(f"AbuseIPDB score: {abuse_score}%")
                    
                    ThreatLog.objects.create(
                        threat_type='malware',
                        target=ip_address,
                        severity='high' if (pulse_count > 5 or abuse_score > 75) else 'medium',
                        description=f"Malicious IP detected. {' | '.join(desc_parts)}.",
                        source='AlienVault OTX & AbuseIPDB',
                        is_active=True
                    )
                
                context['result'] = result
                messages.success(request, f'Successfully analyzed IP: {ip_address}')
            else:
                messages.error(request, 'Unable to retrieve threat intelligence data.')
                context['has_error'] = True
                context['ip_address'] = ip_address
                
        except ValueError:
            messages.error(request, 'Service configuration error.')
            context['has_error'] = True
        except Exception:
            messages.error(request, 'Unable to connect to threat intelligence service.')
            context['has_error'] = True
            context['ip_address'] = ip_address
    
    elif request.method == 'POST':
        ip_address = request.POST.get('ip_address', '').strip()
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        if not ip_address:
            messages.error(request, 'Please enter an IP address.')
            context['has_error'] = True
        elif not ip_pattern.match(ip_address):
            messages.error(request, 'Invalid IP address format.')
            context['has_error'] = True
        else:
            try:
                otx_service = OTXService()
                result = otx_service.lookup_ip(ip_address)
                
                abuse_result = None
                try:
                    abuseipdb_service = AbuseIPDBService()
                    abuse_result = abuseipdb_service.lookup_ip(ip_address)
                    
                    if not abuse_result.get('error', False):
                        result['abuseipdb'] = abuse_result
                        if abuse_result.get('is_abusive', False):
                            result['is_malicious'] = True
                    else:
                        result['abuseipdb'] = None
                except (ValueError, Exception) as e:
                    logger.warning(f"AbuseIPDB lookup failed: {str(e)}")
                    result['abuseipdb'] = None
                
                if not result.get('error', False):
                    threat_detected = result.get('is_malicious', False) or (
                        result.get('abuseipdb') and result['abuseipdb'].get('is_abusive', False)
                    )
                    
                    SearchHistory.objects.create(
                        user=request.user,
                        search_type='ip',
                        query=ip_address,
                        result_found=result.get('found', False),
                        threat_detected=threat_detected
                    )
                    
                    if threat_detected:
                        pulse_count = result.get('pulse_count', 0)
                        abuse_score = result.get('abuseipdb', {}).get('abuse_confidence_score', 0) if result.get('abuseipdb') else 0
                        
                        desc_parts = []
                        if pulse_count > 0:
                            desc_parts.append(f"Found in {pulse_count} OTX pulse(s)")
                        if abuse_score > 0:
                            desc_parts.append(f"AbuseIPDB score: {abuse_score}%")
                        
                        ThreatLog.objects.create(
                            threat_type='malware',
                            target=ip_address,
                            severity='high' if (pulse_count > 5 or abuse_score > 75) else 'medium',
                            description=f"Malicious IP detected. {' | '.join(desc_parts)}.",
                            source='AlienVault OTX & AbuseIPDB',
                            is_active=True
                        )
                    
                    context['result'] = result
                    messages.success(request, f'Successfully analyzed IP: {ip_address}')
                else:
                    messages.error(request, 'Unable to retrieve threat intelligence data.')
                    context['has_error'] = True
                    context['ip_address'] = ip_address
                    
            except ValueError:
                messages.error(request, 'Service configuration error.')
                context['has_error'] = True
            except Exception:
                messages.error(request, 'Unable to connect to threat intelligence service.')
                context['has_error'] = True
                context['ip_address'] = ip_address
    
    recent_searches = SearchHistory.objects.filter(
        user=request.user,
        search_type='ip'
    ).order_by('-searched_at')[:10]
    
    context['recent_searches'] = recent_searches
    return render(request, 'dashboard/ip_lookup.html', context)