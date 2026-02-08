from setuptools import setup, find_packages

with open("requirements.txt") as requirements_file:
    requirements = requirements_file.readlines()

with open("README.md") as readme_file:
    readme = readme_file.read()

setup(
    entry_points={
        "console_scripts": [
            "pypass-server-start = pypass_server:start_server",
        ],
    },
    long_description_content_type="text/markdown",
    packages=find_packages(),
    long_description=readme,
    install_requires=[requirements],
    name="pypass_server",
    version="1.0.4",

)