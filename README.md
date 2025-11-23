# Cyber Threat Intelligence Dashboar

### INF601 - Advanced Programming in Python
### Samuel Amoateng
### Final Project

## Description

A comprehensive Django-based web application designed to monitor, track, and visualize cybersecurity threats in real-time. This dashboard provides security professionals with an intuitive interface to manage threat intelligence data, analyze threat patterns, and generate statistical insights. The application features automated data population capabilities for testing, customizable threat severity levels, and detailed threat analytics to support informed security decision-making.

## Getting Started

### Dependencies

* Python 3.x or higher
* pip (Python package installer)
* Operating System: Windows 10/11, macOS, or Linux
* Django framework
* Required Python packages (specified in requirements.txt):
  * Django
  * Faker (for generating test data)
  * Other dependencies as listed in requirements.txt

### Installing

* Clone or download this repository to your local machine
* Ensure Python 3.x is installed on your system
* No modifications to files/folders are needed after download

### Executing program

#### Step 1: Create and activate virtual environment

**For Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**For Mac/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Step 2: Navigate to project directory
```bash
cd threat_dashboard
```

#### Step 3: Install required dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Set up the database
```bash
python manage.py makemigrations
python manage.py migrate
```

#### Step 5: Create an admin user
```bash
python manage.py createsuperuser
```

#### Step 6: (Optional) Populate with test data
```bash
# Generate 50 threats and 30 days of statistics (default)
python manage.py populate_fake_data

# Or customize the amount of data
python manage.py populate_fake_data --threats 100 --days 60
```

#### Step 7: Start the development server
```bash
python manage.py runserver
```

#### Step 8: Access the application
* Main dashboard: `http://127.0.0.1:8000/`
* Admin panel: `http://127.0.0.1:8000/admin/`

## Help

Common issues and solutions:

**Migration errors:**
```bash
python manage.py migrate --run-syncdb
```

**Check installed packages:**
```bash
pip list
```

**Deactivate virtual environment when finished:**
```bash
deactivate
```

**Verify virtual environment is activated:**
Look for `(venv)` at the beginning of your command prompt

## Authors

Samuel Amoateng

## Version History

* 1.0
    * Initial Release
    * Core dashboard functionality
    * Threat management system
    * Fake data generation for testing
    * Admin panel integration

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, and resources:
* [Django Documentation](https://docs.djangoproject.com/)
* [Faker Python Library](https://faker.readthedocs.io/)
* [awesome-readme](https://github.com/matiassingers/awesome-readme)
* [PurpleBooth](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)
* INF601 - Advanced Programming in Python course materials