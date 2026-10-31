from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hashgauntlet",
    version="3.0.0",
    author="d4rkfl4m3z",
    description="Active Directory credential auditing for blue and purple teams, built on Hashcat",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Nemorous/hashgauntlet",
    project_urls={
        "Documentation": "https://github.com/Nemorous/hashgauntlet#readme",
        "Bug Tracker": "https://github.com/Nemorous/hashgauntlet/issues",
        "Source": "https://github.com/Nemorous/hashgauntlet"
    },
    packages=find_packages(),
    install_requires=["rich", "cryptography", "setuptools"],
    entry_points={"console_scripts": ["hashgauntlet=hash_gauntlet.hashgauntlet:main"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities"
    ],
    license="MIT",
    python_requires='>=3.6',
    include_package_data=True,
)
