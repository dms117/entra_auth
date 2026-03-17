from setuptools import setup, find_packages

setup(
    name="entra-auth",
    version="1.0.0",
    description="Django app for Microsoft Entra ID (Azure AD) authentication via MSAL",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "msal>=1.29.0",
        "requests>=2.32.0",
        "django>=4.2",
    ],
    classifiers=[
        "Framework :: Django",
        "Programming Language :: Python :: 3",
    ],
)
