/**
 * @file      mender-alloc.c
 * @brief     Generic implementation of the Mender memory management functions
 *
 * Copyright Northern.tech AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

void
mender_set_platform_allocation_funcs(void) {
    /* Nothing to do here, the default/fallback is to use the standard functions
       which is what we want here. We just need this function to be
       available. */
    return;
}
