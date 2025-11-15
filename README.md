# Django Application Setup Guide

This guide will walk you through setting up and running the Django application.

## Prerequisites

- Python 3.x installed on your system
- pip (Python package installer)

## Installation & Setup

### 1. Create and Activate Virtual Environment

#### For Windows:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

#### For Mac/Linux:
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### 2. Navigate to Project Directory
```bash
cd threat_dashboard
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup

#### Make Migrations
```bash
python manage.py makemigrations
```

#### Run Migrations
```bash
python manage.py migrate
```

### 5. Create Superuser
```bash
python manage.py createsuperuser
```
Follow the prompts to set up your admin username, email, and password.

### 6. Populate Fake Data (Optional)

For testing purposes, you can populate the database with fake threat data:

```bash
python manage.py populate_fake_data
```

#### Available Options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--threats` | int | 50 | Number of fake threats to generate |
| `--days` | int | 30 | Number of days of statistics to generate |

#### Examples:
```bash
# Generate with default values (50 threats, 30 days of stats)
python manage.py populate_fake_data

# Generate 100 threats and 60 days of statistics
python manage.py populate_fake_data --threats 100 --days 60

# Generate only 20 threats with default days
python manage.py populate_fake_data --threats 20
```

### 7. Start Development Server
```bash
python manage.py runserver
```

The application will be available at `http://127.0.0.1:8000/`

The admin panel can be accessed at `http://127.0.0.1:8000/admin/`

## Deactivating Virtual Environment

When you're done working on the project, you can deactivate the virtual environment:

```bash
deactivate
```

## Troubleshooting

- If you encounter any migration issues, try running `python manage.py migrate --run-syncdb`
- Make sure all dependencies are installed correctly by checking `pip list`
- Ensure your virtual environment is activated before running any Django commands