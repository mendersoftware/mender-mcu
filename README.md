# mender-mcu

## Overview

mender-mcu is a fork of the [mender-mcu-client](https://github.com/joelguittet/mender-mcu-client)
project, created to extend its functionality and provide continued support from Northern.tech, the
creators of [Mender](https://mender.io/). This project is currently under construction, with the
primary goal of enhancing the original work while integrating it more closely with Northern.tech's
suite of products.


## Project Status

This repository is a work in progress. As we continue development, features and functionality may
evolve significantly. We are actively working on expanding the capabilities of the original
mender-mcu-client to better support a wider range of use cases.


## Why Fork?

The decision to fork the original mender-mcu-client was made to:

* **Extend Functionality**: Introduce new features and enhancements that align with the broader
  Mender ecosystem.
* **Provide Official Support**: Ensure that the project receives the necessary attention and
  resources from Northern.tech to meet the needs of the community and enterprise users.


## Getting Started

Since the project is under active development, we recommend watching the repository or checking back
regularly for updates. Detailed documentation and usage instructions will be provided as the project
progresses.

## Testing the Mender MCU Client (POSIX)

### Dependencies
- CMake
- libcurl
- cJSON
- mbedTLS

Example for Ubuntu/Debian:
```
apt install cmake libcurl4-openssl-dev libmbedtls-dev
```
### Building the Client

1. Configure the build:
```
cmake -C CMake_posix_defaults.txt -B build tests
```

2. Build the client:
```
cmake --build build --parallel $(nproc --all)
```

### Running the Client
You can now run and connect the client to e.g. hosted Mender:
```
export MAC_ADDRESS=<mac_address>
export DEVICE_TYPE=<device_type>
export TENANT_TOKEN=<tenant_token>
export ARTIFACT_NAME=<artifact_name>

./build/mender-mcu-client.elf --mac_address=$MAC_ADDRESS --device_type=$DEVICE_TYPE --tenant_token=$TENANT_TOKEN --artifact_name=$ARTIFACT_NAME
```
The mac address is an arbitrary identifier. You can use anything as long as it is unique for each device.

The tenant token can be found under `My organization` in hosted Mender, where it's called `Organization token`.

### Creating an Artifact
Create an artifact (remember to disable compression):
```
./mender-artifact write rootfs-image --compression none --artifact-name <artifact_name> --device-type <device_type> --file <file_name>
```
The `device_type` in the artifact has to match the `device_type` used when running the client.

### Deployment
After creating and uploading the artifact to the server, you should be able to deploy it to the device.

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
