# Tell Me Your Secrets

![CI](https://github.com/valayDave/tell-me-your-secrets/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/tell-me-your-secrets.svg)](https://badge.fury.io/py/tell-me-your-secrets)
![PyPI downloads](https://img.shields.io/pypi/dm/tell-me-your-secrets)


A simple module which finds files with different secrets keys present inside a directory. Secrets derived from 120 different signatures.

## Installation

With [pipx](https://pipxproject.github.io/pipx/):

```bash
pipx install tell-me-your-secrets
```

With Pip:

```bash
pip install tell-me-your-secrets
```

From source:

```bash
git clone git@github.com:valayDave/tell-me-your-secrets.git
cd tell-me-your-secrets
python3 -m venv .env
source .env/bin/activate
pip install .
```

## Module Usage

```bash
tell-me-your-secrets [-h] [-c CONFIG] [-w WRITE] [-f FILTER [FILTER ...]] [-v] [-e] [-g] search_path
```

![](Resources/output_example.gif)

## Usage Examples

- ``tell-me-your-secrets -c new_config.yml /home`` : Find secrets in the home directory according to the provided config file. ``config.yml`` structure provided in the next section.

- ``tell-me-your-secrets /home -f aws microsoft crypto digitalocean ssh sql google`` : Will use the [default config](https://github.com/valayDave/tell-me-your-secrets/blob/master/tell_me_your_secrets/config.yml) and filter signatures according to those keywords.

## Module Configuration

The `config.yml` file contains the configuration for the module. All signatures derived from the config file.

```yaml
blacklisted_extensions: [] # list of extensions to ignore
blacklisted_paths: [] # list of paths to ignore
red_flag_extensions: [] # list of Extensions not be ignored
whitelisted_strings: [] # Add strings which should always be ignored
signatures: # list of signatures to check
  - part: '' # either filename, extension, path or contents
    match: '' # simple text comparison (if no regex element)
    regex: '' # regex pattern (if no match element)
    name: '' # name of the signature
```

## Contributing

- Fork this repo
- Create pull requests against the master branch
- Be sure to add tests for changes or additional functionality
- Ensure that the PR description clearly describes the behaviour of the change
- Ensure that CI tests pass

### Setup environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-test.txt
```
#### Pre-commit

We leverage the [pre-commit](https://pre-commit.com/) framework.

Install git hooks with `pre-commit install`.

Run the checks `pre-commit run --all-files`.

## Module Inspiration

As a sysadmin, when machines are provisioned on the cloud to developers, some recklessly leave secret keys and files behind on those machines. This module helps find such leakages.

## Module Credits

- Signatures Derived from [shhgit](https://github.com/eth0izzle/shhgit)

- Available Signatures :
```
Chef private key, Potential Linux shadow file, Potential Linux passwd file, Docker configuration file, NPM configuration file, Environment configuration file, Contains a private key, AWS Access Key ID Value, AWS Access Key ID, AWS Account ID, AWS Secret Access Key, AWS Session Token, Artifactory, CodeClimate, Facebook access token, Google (GCM) Service account, Stripe API key, Google OAuth Key, Google Cloud API Key
Google OAuth Access Token, Picatic API key, Square Access Token, Square OAuth Secret, PayPal/Braintree Access Token, Amazon MWS Auth Token, Twilo API Key, MailGun API Key, MailChimp API Key, SSH Password, Outlook team, Sauce Token, Slack Token, Slack Webhook, SonarQube Docs API Key, HockeyApp, Username and password in URI, NuGet API Key, Potential cryptographic private key, Log file, Potential cryptographic key bundle, Potential cryptographic key bundle
Potential cryptographic key bundle, Potential cryptographic key bundle, Pidgin OTR private key, OpenVPN client configuration file, Azure service configuration schema file, Remote Desktop connection file, Microsoft SQL database file, Microsoft SQL server compact database file, SQLite database file, SQLite3 database file, Microsoft BitLocker recovery key file
Microsoft BitLocker Trusted Platform Module password file, Windows BitLocker full volume encrypted data file, Java keystore file, Password Safe database file, Ruby On Rails secret token configuration file, Carrierwave configuration file, Potential Ruby On Rails database configuration file, OmniAuth configuration file, Django configuration file
1Password password manager database file, Apple Keychain database file, Network traffic capture file, GnuCash database file, Jenkins publish over SSH plugin file, Potential Jenkins credentials file, KDE Wallet Manager database file, Potential MediaWiki configuration file, Tunnelblick VPN configuration file, Sequel Pro MySQL database manager bookmark file, Little Snitch firewall configuration file, Day One journal file, Potential jrnl journal file, Chef Knife configuration file, cPanel backup ProFTPd credentials file
Robomongo MongoDB manager configuration file, FileZilla FTP configuration file, FileZilla FTP recent servers file, Ventrilo server configuration file, Terraform variable config file, Shell configuration file, Shell configuration file, Shell configuration file, Private SSH key, Private SSH key, Private SSH key, Private SSH key, SSH configuration file, Potential cryptographic private key, Shell command history file
MySQL client command history file, PostgreSQL client command history file, PostgreSQL password file, Ruby IRB console history file, Pidgin chat client account configuration file, Hexchat/XChat IRC client server list configuration file, Irssi IRC client configuration file, Recon-ng web reconnaissance framework API key database, DBeaver SQL database manager configuration file, Mutt e-mail client configuration file, S3cmd configuration file, AWS CLI credentials file, SFTP connection configuration file, T command-line Twitter client configuration file, Shell configuration file
Shell profile configuration file, Shell command alias configuration file, PHP configuration file, GNOME Keyring database file, KeePass password manager database file, SQL dump file, Apache htpasswd file, Configuration file for auto-login process, Rubygems credentials file, Tugboat DigitalOcean management tool configuration, DigitalOcean doctl command-line client configuration file, git-credential-store helper credentials file, GitHub Hub command-line client configuration file, Git configuration file
```

## Author

- [Valay Dave](valaygaurang@gmail.com)

## Licence

MIT
