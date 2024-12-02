from setuptools import setup, find_packages
from pathlib import Path

setup(
    name="azionify",
    version="1.0.0",
    description="A tool to convert Akamai Terraform configurations into Azion Terraform configurations.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Andre Lehdermann Silveira",
    author_email="support@azion.com",
    url="https://github.com/aziontech/azionify",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "python-hcl2",
    ],
    extras_require={
        "dev": ["pytest", "flake8", "black"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "azionify=main:main",
        ],
    },
)


