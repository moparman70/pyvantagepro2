'''
    PyVantagepro3
    ------------

    Communication tool for the Davis VP2.


'''
import re
import sys
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))


setup(
    name='pyvantagepro3',
    version='0.0.12',
    url='https://github.com/moparman70/pyvantagepro2',
    license='GNU GPL v3',
    description='Communication tool for the Davis VP2',
    author='',
    author_email='',
    maintainer='',
    maintainer_email='',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet',
        'Topic :: Utilities',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    packages=find_packages(),
    zip_safe=False,
    install_requires=[],
    entry_points={
        'console_scripts': [
            'pyvantagepro2 = pyvantagepro3.__init__:main'
        ],
    },
)
