# mender-mcu

## Overview

mender-mcu is a fork of the [mender-mcu-client](https://github.com/joelguittet/mender-mcu-client)
project, created to extend its functionality and provide continued support from Northern.tech, the
creators of [Mender](https://mender.io/).

-------------------------------------------------------------------------------

![Mender logo](https://github.com/mendersoftware/mender/raw/master/mender_logo.png)

## Why Fork?

The decision to fork the original mender-mcu-client was made to:

* **Extend Functionality**: Introduce new features and enhancements that align with the broader
  Mender ecosystem.
* **Provide Official Support**: Ensure that the project receives the necessary attention and
  resources from Northern.tech to meet the needs of the community and enterprise users.

## Get started

`mender-mcu` runs on Zephyr and FreeRTOS (ESP-IDF, preview). How to integrate, configure and build
it for each operating system is described in the [Mender documentation](https://docs.mender.io):

* [Get started: Microcontroller](https://docs.mender.io/get-started/microcontroller-preview)
* [Operating System updates: Zephyr](https://docs.mender.io/operating-system-updates-zephyr)
* [Operating System updates: FreeRTOS](https://docs.mender.io/operating-system-updates-freertos)
* [Troubleshoot: Mender MCU](https://docs.mender.io/troubleshoot/mender-mcu)

The reference application [mender-mcu-integration](https://github.com/mendersoftware/mender-mcu-integration)
shows how to use `mender-mcu`: the `main` branch for Zephyr and the `esp-idf` branch for ESP-IDF.

### Boards

The reference board for `mender-mcu` is the [ESP32-S3-DevKitC](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/index.html).

## API

The public API is in [`include/mender`](include/mender). See the Mender documentation for how to use it
on [Zephyr](https://docs.mender.io/operating-system-updates-zephyr/customize-mender-mcu) and
[FreeRTOS](https://docs.mender.io/operating-system-updates-freertos/board-integration).

## Contributing

We welcome and ask for your contribution. If you would like to contribute to
Mender, please read our guide on how to best get started
[contributing code or documentation](https://github.com/mendersoftware/mender/blob/master/CONTRIBUTING.md).


## License

Mender is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/mendersoftware/mender-mcu/blob/master/LICENSE)
for the full license text.

The `mender-mcu` project is a fork from [Joel Guittet's
`mender-mcu-client`](https://github.com/joelguittet/mender-mcu-client) licensed under the Apache
License, Version 2.0. See
[LICENSE](https://github.com/joelguittet/mender-mcu-client/blob/master/LICENSE)


## Security disclosure

We take security very seriously. If you come across any issue regarding
security, please disclose the information by sending an email to
[security@mender.io](security@mender.io). Please do not create a new public
issue. We thank you in advance for your cooperation.


## Connect with us

* Join the [Mender Hub discussion forum](https://hub.mender.io)
* Follow us on [Twitter](https://twitter.com/mender_io). Please
  feel free to tweet us questions.
* Fork us on [Github](https://github.com/mendersoftware)
* Create an issue in the [bugtracker](https://northerntech.atlassian.net/projects/MEN)
* Email us at [contact@mender.io](mailto:contact@mender.io)
* Connect to the [#mender IRC channel on Libera](https://web.libera.chat/?#mender)
