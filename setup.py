# setup.py — WiperX installation
from setuptools import setup, find_packages

# Core runtime deps: what `wiperx scan`, `wiperx wipe`, the erase commands and
# the Flask app need. Keep in sync with requirements.txt.
CORE = [
    "click>=8.1",
    "colorama>=0.4.6",
    "tabulate>=0.9",
    "paramiko>=3.4",
    "Flask>=3.0,<4",
    "Flask-Login>=0.6.3",
    "Flask-WTF>=1.2",
    "Werkzeug>=3.0,<4",
    "Jinja2>=3.1",
    "reportlab>=4.1",
    "psutil>=5.9",
    "bcrypt>=4.1",
    "cryptography>=42",
    "python-json-logger>=2.0",
    "python-dotenv>=1.0",
]

setup(
    name="wiperx",
    version="1.0.0",
    description="Cross-Platform Disk Wiping System",
    packages=find_packages(),
    install_requires=CORE,
    extras_require={
        # Module 3 forensic carving / recovery. python-magic also needs the
        # libmagic system library.
        "forensics": [
            "pytsk3>=20250312",
            "python-magic>=0.4.27",
            "Pillow>=11.0",
            "pypdf>=4.2",
            "mutagen>=1.47",
        ],
        "remote-windows": ["pywinrm>=0.4.3", "requests-credssp>=2.0"],
        "dev": ["pytest>=8.1", "pytest-mock>=3.12", "pytest-cov>=5.0",
                "black>=24.3", "flake8>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "wiperx=cli.wiperx_cli:cli",
        ],
    },
    python_requires=">=3.10",
)
