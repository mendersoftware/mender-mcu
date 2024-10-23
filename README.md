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

While working on the first release of the project, we consider the `main` branch to be experimental,
while the stable versions can be found in separate Git branches like `vX.Y-alias`.


## Why Fork?

The decision to fork the original mender-mcu-client was made to:

* **Extend Functionality**: Introduce new features and enhancements that align with the broader
  Mender ecosystem.
* **Provide Official Support**: Ensure that the project receives the necessary attention and
  resources from Northern.tech to meet the needs of the community and enterprise users.


## Get Started

Since the project is under active development, we recommend watching the repository or checking back
regularly for updates. Detailed documentation and usage instructions will be provided as the project
progresses.


## Get started with Zephyr OS

For using `mender-mcu` for the first time, we strongly recommend you start with our Zephyr reference
application.

It can be found in the repository
[mender-mcu-integration](https://github.com/mendersoftware/mender-mcu-integration). The policy is
that the reference application's `main` branch will follow the latest stable branch of `mender-mcu`
(this repository).

In the `mender-mcu-repository` you will find:
* A reference `west` workspace for Zephyr OS builds, including `CMake` and `KConfig` configurations.
* Sample application for how to use `mender-mcu` APIs.
* A list of boards that we have so far tested.

We recommend starting there to understand how we have designed our solution and then coming back
here for more in-depth information.


### The Mender client API

The main API is exposed in [`mender-client.h`](include/mender-client.h). The most notable parts are:

* Identity callback. The user needs to provide a callback that will return the identity. In most
cases, this would be reading a unique device number like a MAC address. Read more about
[Mender identity in Mender Docs](https://docs.mender.io/overview/identity).

* Network connect / Network release callbacks. In systems where the network is not always available,
the client will invoke the network connect callback before doing operations that require
connectivity (for example, checking for an update). Once network operations are completed, the
network release callback will be invoked. They can be set to `NULL` if the network is assumed to be
always ready.

* Restart callback. To be called to trigger a device reset, for example after a fatal error.

* Inventory setting. There is an explicit call to set the inventory. This will update the internal
inventory of the client and sent to the Mender Server in the next inventory report.

See the source code for more.


### Update Modules API

Mender MCU models the Update Modules API which we have been using in the regular Mender client for
years. Refer to the [Update Modules chapter in Mender
Docs](https://docs.mender.io/artifact-creation/create-a-custom-update-module) for an introduction.
In Mender MCU, the modules are not "executables" but rather rather a custom C function that is
integrated with the client to handle each type of update.

#### Update Modules State Machine

As stated above, an Update Module for Mender MCU is set of customizable C functions. Concretely,
once created, all Update Modules are identified by a C struct in
[mender-zephyr-image-update-module.h](include/mender-zephyr-image-update-module.h). The
most important part of the struct is the array of callbacks, one to be called for each state.

See [the state machine workflow
diagram](https://docs.mender.io/artifact-creation/create-a-custom-update-module#the-state-machine-workflow)
to learn about the flow between each state. An Update Module does not need to implement all of them,
only the ones that are relevant for a particular type of update.

We provide the `zephyr-image` Update Module, which implements the update process for a Zephyr OS
update integrated with MCUboot. Its [source code](core/src/mender-zephyr-image-update-module.c)
can be inspected for inspiration and a better understanding of the expected behavior of each state.

After writing the code, you need to register the Update Module into the Mender MCU. See the register
update module function in [`mender-client.h`](include/mender-client.h).


## Known issues

There are several outstanding known issues with the current code:

* No proper scheduler. Internal ticket at [MEN-7536](https://northerntech.atlassian.net/browse/MEN-7536).
  So far we have written a minimal scheduling single threaded logic, that only allow for one
  operation at a time. The client run gets scheduled every polling interval and would conduct the
  full update (if any) at once. We plan to redesign it better to allow for re-entry and resource
  protection, so that we could have inventory being reported independently, for example.

* The inventory feature is disabled.
  Related to the above, there is no inventory reporting at the moment.

* Freeze during a deployment. Internal ticket at MEN-7562](https://northerntech.atlassian.net/browse/MEN-7562).
  We are experiencing that the client can freeze during context switch, when attending a kernel's
  ISR, for example. This can happen during the download of the update.

* Logging disabled.
  Related to the above, as a temporary mitigation we have disabled logging from the client which
  makes the risk of these freezes very small, although not completely gone.


## Experimental: testing the Mender MCU Client with POSIX

### Dependencies
- CMake
- libcurl
- cJSON

Example for Ubuntu/Debian:
```
apt install cmake libcurl4-openssl-dev libcjson-dev
```
### Building the Client

1. Configure the build:
```
cmake -C cmake/CMake_posix_defaults.txt -B build tests/smoke
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
./mender-artifact write module-image -T zephyr-image --compression none --artifact-name <artifact_name> --device-type <device_type> --file <file_name>
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
