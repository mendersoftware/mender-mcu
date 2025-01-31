#!/bin/bash
# @file      check_allocations.sh
# @brief     Check that memory allocations are done using our functions
#
# Copyright Northern.tech AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

bad_files=$(git grep -Pl '\b(malloc|calloc|realloc|free)\s*\(' | grep -Pv '(tests/|core/src/mender-alloc\.c)')
if [ -n "$bad_files" ]; then
  for file in $bad_files; do
    echo "=============================="
    echo "Bad memory allocations in $file (or a broken check):"
    grep -HnP '\b(malloc|calloc|realloc|free)\s*\(' "$file"
    echo "=============================="
  done
fi
