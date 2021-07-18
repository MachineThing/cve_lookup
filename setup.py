from setuptools import setup
import pathlib
long_description = (pathlib.Path(__file__).parent/'README.md').read_text(encoding='utf-8')

setup(name='cve_lookup',
      version='0.0.1',
      description='Look up CVEs and get details about them.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/machinething/cve_lookup',
      author='MachineThing',
      #author_email='N/A',
      license='MIT',
      packages=['cve_lookup'],
      zip_safe=False,
      classifiers=[
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
      ],
      keywords='cve, simple, requests, search, cvss',
      python_requires='>3.8,<4',
      install_requires=[
        'beautifulsoup4',
        'requests'
      ],
      entry_points={
        'console_scripts': [
            'cve_lookup=cve_lookup:main'
        ]
      },
      project_urls={
        'Repository':'https://github.com/machinething/cve_lookup',
        'Issues':'https://github.com/machinething/cve_lookup/issues',
        'MachineThing':'https://masonfisher.net'
      }
)
