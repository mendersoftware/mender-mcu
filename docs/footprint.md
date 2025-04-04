# Mender MCU memory footprint

The Mender MCU project is designed with memory footprint in mind. This document
estimates the memory footprint of the project. This is, the amount of code that
will end up in the ROM section of the memory and the amount of RAM required.

## Zephyr OS

For Zephyr OS, we use
[Zephyr OS built-in optimization tools](https://docs.zephyrproject.org/latest/develop/optimizations/tools.html#footprint-and-memory-usage)
to analyze RAM and ROM usage in generated images.

The following measurements:
* Use board ESP32S3 DevkitC
* Use default feature set of Mender MCU Zephyr module
* Set the log level for Mender MCU to Warning

| Mender MCU | Zephyr OS   | Code in ROM | Static RAM | Dynamic RAM |
| -------    | ----------- | ----------- | ---------- | ----------- |
| preview    | v4.0.0      | 33 KiB      | 15 KiB     | 8~12 KiB    |

Dynamic RAM is user configurable through Kconfig parameter `MENDER_HEAP_SIZE`. On our reference board, 8 to 12 KiB is recommended.
