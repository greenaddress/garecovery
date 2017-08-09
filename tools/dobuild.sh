#! /usr/bin/env bash
set -e

python setup.py pep8 --max-line-length=100
python setup.py test
python setup.py sdist
