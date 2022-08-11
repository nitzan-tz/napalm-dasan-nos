"""setup.py file."""

from setuptools import setup, find_packages

__author__ = 'Warren Ashcroft <warren.ashcroft@4thu.co.uk>'

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

setup(
    name="napalm-dasan-nos",
    version="1.0.0",
    packages=find_packages(),
    author="Warren Ashcroft",
    author_email="warren.ashcroft@4thu.co.uk",
    description="NAPALM driver for Dasan NOS",
    long_description_content_type="text/markdown",
    long_description=long_description,
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-dasan-nos",
    include_package_data=True,
    install_requires=reqs,
)
