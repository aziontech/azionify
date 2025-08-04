import os
from setuptools import setup, find_packages

# Read README.md safely
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, encoding="utf-8") as f:
            return f.read()
    return "Azionify - CLI tool for converting Terraform configurations to Azion-compatible format"

setup(
    name="azionify",
    version="1.0.0",
    description="CLI tool to convert Terraform configurations from various CDNs into Azion-compatible Terraform configurations",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Andre Lehdermann Silveira",
    author_email="support@azion.com",
    url="https://github.com/aziontech/azionify",
    project_urls={
        "Bug Reports": "https://github.com/aziontech/azionify/issues",
        "Source": "https://github.com/aziontech/azionify",
        "Documentation": "https://github.com/aziontech/azionify#readme",
    },
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "python-hcl2>=4.0.0",
        "lark>=1.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "flake8>=4.0",
            "black>=22.0",
            "pylint>=2.0",
        ]
    },
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Software Development :: Build Tools",
        "Topic :: System :: Systems Administration",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    keywords="terraform azion cdn akamai migration devops infrastructure",
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "azionify=azionify.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
