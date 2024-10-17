# Project structure

## Current structure

```
├── cmake
│   ├── CMake_defaults.txt
│   ├── CMake_posix_defaults.txt
│   └── CMake_weak_defaults.txt
├── **CMakeLists.txt**
├── core
│   └── src
│       ├── mender-api.c
│       ├── mender-artifact.c
│       ├── mender-client.c
│       ├── ...
├── include
│   ├── mender-api.h
│   ├── mender-artifact.h
│   ├── mender-client.h
│   ├── ...
│   ├── mender-flash.h
│   ├── mender-log.h
│   ├── mender-scheduler.h
│   ├── mender-storage.h
│   ├── ...
├── platform
│   ├── flash
│   │   ├── generic
│   │   │   └── weak
│   │   │       └── src
│   │   │           └── mender-flash.c
│   │   ├── posix
│   │   │   └── src
│   │   │       └── mender-flash.c
│   │   └── zephyr
│   │       └── src
│   │           └── mender-flash.c
│   ├── ...
├── tests
│   ├── **CMakeLists.txt**
│   ├── mocks
│   │   ├── cjson
│   │   │   └── CMakeLists.txt
│   │   ├── CMakeLists.txt
│   │   └── mbedtls
│   │       └── CMakeLists.txt
│   └── src
│       └── main.c
├── west.yml
└── zephyr
    ├── **CMakeLists.txt**
    ├── Kconfig
    └── module.yml
```

Main issues:
* root CMakeLists.txt is a target to be _included_ and then extended. Only used for tests.
* zephyr project has a copy of the sources. As per today they are already discrepancies

From CMake point of view, a repository should either be:

* Built from top to down, where each directory represents a target (a library, a binary) with
one CMakeLists.txt. The user options are parsed in the top dir and passed along. `mender` style.

* A set of projects, build from wherever you want, but then there is no root CMakeLists. This is
the setup that I have seen in multi platform rtos projects. For example:

  * https://github.com/golioth/golioth-firmware-sdk/tree/main
  * https://github.com/mcu-tools/mcuboot/tree/main

I think that the reason is that both Zephyr OS and FreeRTOS provide a set of CMake "module" which
defines macros that need to be used _before_ you add your library and sources.

## Proposed rework

Goals:
* Do not duplicate sources list
* Have a clear "entry point" per OS platform: Zephyr OS, FreeRTOS, POSIX/Linux
* Keep resemblance with community project

```
├── cmake
│   ├── **mender_mcu_cache_default.txt**
│   └── **mender_mcu_sources.txt**
├── core
│   └── src
│       ├── ...
├── include
│   ├── ...
├── platform
│   ├── ...
├── target
│   ├── freertos
│   │   └── **CMakeLists.txt**
│   ├── posix
│   │   └── **CMakeLists.txt**
│   └── zephyr
│   │   └── **CMakeLists.txt**
│   │   └── Kconfig
├── tests
│   ├── CMakeLists.txt
│   ├── mocks
│   │   ├── cjson
│   │   │   └── CMakeLists.txt
│   │   ├── CMakeLists.txt
│   │   └── mbedtls
│   │       └── CMakeLists.txt
│   └── src
│       └── main.c
├── ??west.yml??
└── zephyr
    └── **module.yml**
```

## If we could take it further...

Goals:
* Do not duplicate sources list
* Have a clear "entry point" per OS platform: Zephyr OS, FreeRTOS, POSIX/Linux
* ~~Keep resemblance with community project~~

```
├── cmake
│   ├── ...
├── src
│   └── core
│   │   ├── ...
│   ├── flash
│   │   ├── platform
│   │   │   ├── generic
│   │   │   │   └── weak
│   │   │   │       └── src
│   │   │   │           └── mender-flash.c
│   │   │   ├── posix
│   │   │   │   └── src
│   │   │   │       └── mender-flash.c
│   │   │   └── zephyr
│   │   │       └── src
│   │   │           └── mender-flash.c
├── include
│   ├── ...
├── **platform**
│   ├── freertos
│   │   └── CMakeLists.txt
│   ├── posix
│   │   └── CMakeLists.txt
│   └── zephyr
│   │   └── CMakeLists.txt
│   │   └── Kconfig
├── tests
│   ├── ...
└── zephyr
    └── **module.yml**
```