from typing import List

import setuptools

from tell_me_your_secrets import __version__


def get_long_description() -> str:
    with open('README.md') as fh:
        return fh.read()


def get_required() -> List[str]:
    with open('requirements.txt') as fh:
        return fh.read().splitlines()


setuptools.setup(
    name='tell_me_your_secrets',
    packages=setuptools.find_packages(),
    version=__version__,
    license='MIT',
    description='A simple module which finds files with different secrets keys present inside a directory.'
                'Secrets derived from 120 different signatures.',
    author='Valay Dave',
    include_package_data=True,
    author_email='valaygaurang@gmail.com',
    url='https://github.com/valayDave/tell-me-your-secrets',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    keywords=['Security', 'SSH', 'Secret Keys', 'SysAdmin'],
    install_requires=get_required(),
    python_requires='>=3.6',
    entry_points={
        'console_scripts': ['tell-me-your-secrets=tell_me_your_secrets.__main__:run_service'],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
