from setuptools import setup

setup(name='cve_lookup',
      version='0.1',
      description='Look up CVEs and get details about them.',
      url='https://github.com/machinething/cve_lookup',
      author='MachineThing',
      author_email='N/A',
      license='MIT',
      packages=['cve_lookup'],
      zip_safe=False,
      classifiers=[
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        ''
      ],
      python_requires='>3.8',
      install_requires=[
        'beautifulsoup4',
        'requests'
      ]
)
