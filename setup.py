from setuptools import setup, find_packages

setup(
    name="appguard",
    version="1.0.0",
    description="LLM-Powered Android App Security Analyzer",
    author="AppGuard",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.0",
        "requests>=2.31",
        "ollama>=0.4",
    ],
    entry_points={
        "console_scripts": [
            "appguard=appguard.main:main",
        ],
    },
)
