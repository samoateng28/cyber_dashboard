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