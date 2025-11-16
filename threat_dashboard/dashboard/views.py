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
def ip_lookup_view(request):
    """View for IP address lookup using OTX API"""
    context = {
        'user': request.user,
        'ip_address': '',
        'result': None,
        'error': None,
        'has_error': False,
    }
    
    if request.method == 'POST':
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
                # Initialize OTX service
                otx_service = OTXService()
                
                # Perform lookup
                result = otx_service.lookup_ip(ip_address)
                
                # Only save search history if API call succeeded (no error)
                if not result.get('error', False):
                    # Save search history only when API call was successful
                    SearchHistory.objects.create(
                        user=request.user,
                        search_type='ip',
                        query=ip_address,
                        result_found=result.get('found', False),
                        threat_detected=result.get('is_malicious', False)
                    )
                    
                    # If malicious, optionally create a ThreatLog entry
                    if result.get('is_malicious', False):
                        pulse_count = result.get('pulse_count', 0)
                        ThreatLog.objects.create(
                            threat_type='malware',
                            target=ip_address,
                            severity='high' if pulse_count > 5 else 'medium',
                            description=f"Malicious IP detected via OTX. Found in {pulse_count} threat intelligence pulse(s).",
                            source='AlienVault OTX',
                            is_active=True
                        )
                    
                    context['result'] = result
                    messages.success(request, f'Successfully analyzed IP address: {ip_address}')
                else:
                    # API call failed - show user-friendly error
                    messages.error(request, 'Unable to retrieve threat intelligence data. Please check your connection and try again.')
                    context['has_error'] = True
                    context['ip_address'] = ip_address
                    
            except ValueError:
                # Configuration error - show generic message
                messages.error(request, 'Service configuration error. Please contact support.')
                context['has_error'] = True
            except Exception as e:
                # Network errors, etc. - show user-friendly message
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