import setuptools

setuptools.setup(
    name="vomsimporter-indigoiam",
    version="0.0.1",
    author="Andrea Ceccanti",
    author_email="andrea.ceccanti@cnaf.infn.it",
    url="https://github.com/indigoiam/voms-importer",
    description="A IAM VOMS import script",
    python_requires=">=3.6",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ]
)
