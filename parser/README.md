# TOSS STIG Parser

This sub-project contains code for parsing the TOSS STIG documents (primarily the XML files) for use in the writing of the actual checker, Ansible playbooks, etc.

## Getting Started

This project uses [Pipenv](https://pipenv.pypa.io) for development. Check out their documentation for more details, but what follows is a quick start (note some of the command output may not look exactly the same in your environment):

```shell
# Change in to the parser directory
$ cd toss-stig/parser/

# Update / install your pipenv environment
$ pipenv sync
Creating a virtualenv for this project...
...snip...
✔ Successfully created virtual environment!
Virtualenv location: /Users/lee1001/.local/share/virtualenvs/parser-OQz2eN8i
Installing dependencies from Pipfile.lock (e3db3e)...
To activate this projects virtualenv, run pipenv shell.
Alternatively, run a command inside the virtualenv with pipenv run.
All dependencies are now up-to-date!

# Test that things worked properly
# 1) Activate the virtual environment
$ pipenv shell
Launching subshell in virtual environment...

# 2) Run the parser script
$ ./parser.py --help
Usage: parser.py [OPTIONS] INPUT_FILE

Options:
  --template-file PATH
  --output-dir PATH
  --help                Show this message and exit.
```
