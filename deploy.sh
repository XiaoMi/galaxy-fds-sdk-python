#!/bin/bash

restore() {
  git checkout -- fds/fds_client_example.py
}

git diff --quiet || exit 1

set -x

rm -rf UNKNOWN.egg-info
rm -rf galaxy_fds_sdk.egg-info
rm -rf dist

set -e

rm ./fds/fds_client_example.py # cannot upload ak sk in example

trap restore EXIT

python setup.py sdist
python setup.py register
python setup.py sdist upload
