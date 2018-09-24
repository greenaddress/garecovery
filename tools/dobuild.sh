#! /usr/bin/env bash
set -e

pycodestyle --max-line-length=100
python setup.py test
python setup.py sdist
