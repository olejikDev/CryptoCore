from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.7.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[],
    entry_points={
        "console_scripts": [
            "cryptocore=cryptocore.cli_parser:main",
        ],
    },
)