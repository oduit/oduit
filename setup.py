# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from setuptools import setup

setup(
    use_scm_version={"write_to": "oduit/_version.py"},
    setup_requires=["setuptools_scm"],
)
