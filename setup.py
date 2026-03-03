# setup.py — WiperX CLI installation
from setuptools import setup, find_packages

setup(
    name="wiperx",
    version="1.0.0",
    description="Production-Grade Cross-Platform Disk Wiping System",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.7",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "paramiko>=3.4.0",
        "Flask>=3.0.2",
        "Flask-Login>=0.6.3",
        "reportlab>=4.1.0",
        "psutil>=5.9.8",
        "bcrypt>=4.1.2",
    ],
    entry_points={
        "console_scripts": [
            "wiperx=cli.wiperx_cli:cli",
        ],
    },
    python_requires=">=3.10",
)
