#! /usr/bin/env bash
set -e

pycodestyle --max-line-length=100
python3 setup.py test
python3 setup.py sdist
