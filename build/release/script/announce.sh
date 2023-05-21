#!/usr/bin/env bash

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -o pipefail
set -e

RELEASE_DIR="$(cd "$(dirname "$0")"/..; pwd)"

######### Please modify the variables ##########
# release version, e.g. 0.1.0
release_version=${release_version:-""}
################################################

if [[ -z $release_version ]]; then
  echo "Please input release version"
  exit 1
fi

echo "Release version: ${release_version}"

RELEASE_TEMP_DIR=${RELEASE_DIR}/tmp
mkdir -p ${RELEASE_TEMP_DIR}
ANNOUNCE=${RELEASE_TEMP_DIR}/${release_version}_announce.temp

cat >$ANNOUNCE<<EOF
Title: [ANNOUNCE] Apache Kyuubi Shaded released ${release_version}

Content:
Hi all,

The Apache Kyuubi community is pleased to announce that
Apache Kyuubi Shaded ${release_version} has been released!

The full release notes are available at:
Release Notes: https://kyuubi.apache.org/shaded-release/${release_version}.html

To learn more about Apache Kyuubi, please see
https://kyuubi.apache.org/

Kyuubi Resources:
- Issue: https://github.com/apache/kyuubi/issues
- Mailing list: dev@kyuubi.apache.org

We would like to thank all contributors of the Kyuubi community
who made this release possible!

Thanks,
On behalf of Apache Kyuubi community
EOF

echo "please Use announce@apache.org, dev@kyuubi.apache.org
see announce content in $ANNOUNCE"
