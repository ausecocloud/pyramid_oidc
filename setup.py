from setuptools import setup, find_packages

version = '0.1'

setup(
    name='pyramid_oidc',
    version=version,
    description="Pyramid OIDC authentication",
    long_description=(open("README.rst").read() + "\n\n" +
                      open("HISTORY.rst").read()),
    classifiers=[
        "Development Status :: 1 - Alpha",
        "Environment :: Web Environment",
        "Framework :: Pyramid",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License"
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    keywords='python pyramid openidconnect oidc',
    author='',
    author_email='',
    url='https://github.com/ausecocloud/pyramid_oidc',
    license='Apache License 2.0',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=[],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'setuptools',
        'pyramid',
        'python-jose',
        'oauthlib',            #[rsa,signedtoken,signals]
        'requests[security]',  #[security,socks]
        'requests-oauthlib',   #[rsa]
        'dogpile.cache'
    ],
    extras_require={
        'test': [
        ],
    }
)
