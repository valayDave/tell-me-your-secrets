import setuptools

setuptools.setup(
    # How you named your package folder (MyLib)
    name='tell_me_your_secrets',
    packages=setuptools.find_packages(),
    version='1.63',      # Start with a small number and increase it with every change you make
    # Chose a license from here: https://help.github.com/articles/licensing-a-repository
    license='MIT',
    # Give a short description about your library
    description='A simple module which finds files with different secrets keys present inside a directory. Secrets derived from 120 different signatures.',
    author='Valay Dave',                   # Type in your name
    include_package_data=True,
    author_email='valaygaurang@gmail.com',      # Type in your E-Mail
    # Provide either the link to your github or to your website
    url='https://github.com/valayDave/tell-me-your-secrets',
    
    # Keywords that define your package best
    keywords=['Security', 'SSH', 'Secret Keys', 'SysAdmin'],
    install_requires=[            # I get to this in a second
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
        # Define that your audience are developers
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',   # Again, pick a license
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)