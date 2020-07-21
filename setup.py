import setuptools

with open('Readme.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='tell_me_your_secrets',
    packages=setuptools.find_packages(),
    version='1.77',
    license='MIT',
    description='A simple module which finds files with different secrets keys present inside a directory. Secrets '
                'derived from 120 different signatures.',
    author='Valay Dave',
    include_package_data=True,
    author_email='valaygaurang@gmail.com',
    url='https://github.com/valayDave/tell-me-your-secrets',
    long_description=long_description,
    long_description_content_type="text/markdown",
    # Keywords that define your package best
    keywords=['Security', 'SSH', 'Secret Keys', 'SysAdmin'],
    install_requires=[
        'pyyaml',
        'pandas',
    ],
    python_requires='>=3.4',
    entry_points={
        'console_scripts': ['tell-me-your-secrets=tell_me_your_secrets.__main__:run_service'],
    },
    classifiers=[
        # Chose either "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
