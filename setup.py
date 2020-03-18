from setuptools import setup, find_packages

with open("README.md", "r") as fh: 
    long_description = fh.read()

setup(
    name="IDontSpeakSSL",
    version="1.1",
    author="Florian Nivette",
    author_email="fnivette@bishopfox.com",
    description="parallelize sslyze scans.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BishopFox/IDontSpeakSSL",
    packages=find_packages(),
    package_data={'idontspeakssl': [
		'data/config/*.json',
		'data/resources/web_report/js/*.js',
		'data/resources/web_report/css/*.css',
		'data/resources/bin/*'
		]},
    include_package_data=True,
    install_requires=[
        "yattag",
        "termcolor",
        "click",
		"cryptography<2.6",
        "sslyze",
		"pyOpenSSL<19.1.0"
    ],
    entry_points = { 
        'console_scripts': [
            'idontspeakssl = idontspeakssl.__main__:run'
        ]
    }   
)
