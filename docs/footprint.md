# Mender MCU memory footprint

The Mender MCU project is designed with memory footprint in mind. This document
estimates the memory footprint of the client.

Measuring the memory footprint of a C library in isolation is inherently
difficult. The final size depends not only on system-level factors—such as
processor architecture and compiler optimization settings—but also on how the
library is used within a larger project. Only the parts of the code that are
actually referenced will be retained during linking, while unused sections may
be discarded, further affecting the measured footprint.

The Mender MCU client also has dependencies that have a major impact on the
total memory footprint. See Dependencies below for more details.

## Zephyr OS

The Zephyr Project provides
[optimization tools](https://docs.zephyrproject.org/latest/develop/optimizations/tools.html#footprint-and-memory-usage)
to let us analyse Footprint and Memory Usage and Data Structures using different
build system targets.

For one specific board and build configuration, the tools will give us a good
insight on the size of the objects that will be built. That is, the maximum
amount of code that ends up in the ROM section of the memory and the amount of
RAM required (statically allocated objects).

From the tree breakdown of the objects that the tool produces, we can then take
the numbers for the Mender MCU Zephyr module.

### Mender MCU Zephyr Module ROM and RAM estimation for ESP3S3 reference board

The numbers in this table are extracted from a build with the following properties:

* Use board [ESP32-S3-DevKitC](https://docs.zephyrproject.org/latest/boards/espressif/esp32s3_devkitc/doc/index.html)
* Built through [Mender MCU reference application](https://github.com/mendersoftware/mender-mcu-integration)
* Use [default feature set](https://github.com/mendersoftware/mender-mcu/blob/main/target/zephyr/Kconfig) of Mender MCU Zephyr module, except:
* Set the log level for Mender MCU to Warning (`CONFIG_MENDER_LOG_LEVEL_WRN=y`)

| Mender MCU | Zephyr OS   | ROM usage | RAM usage |
| -------    | ----------- | --------- | --------- |
| preview    | v4.0.0      | 33 KiB    | 15 KiB    |

### RAM usage configuration

Most of the RAM usage for Mender MCU is configured with the following two parameters:

* `MENDER_HEAP_SIZE`: Heap size for Mender MCU to use. It defines tha maximum
heap memory available for Mender to use when allocating from its own heap
(recommended behavior). The default value is 8 KiB.

* `MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE`: Stack size for Mender MCU work queue
to use. The default value is 6 KiB.

The defaults are known to work for the reference board and regular operations,
but could or might need to be adjusted for other integrations.

### Dependencies

Mender MCU Zephyr module has one external dependency:

* [cJSON Zephyr module](https://github.com/mendersoftware/cjson-zephyr)

And several dependencies within the Zephyr Project. Most notably:

* Network stack: NETWORKING / NET_TCP / NET_SOCKETS / HTTP_CLIENT
* Mbed TLS
* Non-volatile storage (NVS)
