from setuptools import setup, find_packages

packages = find_packages()
print(f"DEBUG: packages found = {packages}")  # will show in docker build output

setup(
    name="entra_auth",
    version="1.0.0",
    description="Django app for Microsoft Entra ID (Azure AD) authentication via MSAL",
    packages=packages,
    package_dir={"": "."},
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