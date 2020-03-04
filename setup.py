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
    package_data={},
    include_package_data=True,
    install_requires=[
        "yattag",
        "termcolor",
        "click",
        "sslyze"
    ],
    entry_points = { 
        'console_scripts': [
            'idontspeakssl = idontspeakssl.__main__:run'
        ]
    }   
)
