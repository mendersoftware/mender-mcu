# mender-mcu

## Overview

mender-mcu is a fork of the [mender-mcu-client](https://github.com/joelguittet/mender-mcu-client)
project, created to extend its functionality and provide continued support from Northern.tech, the
creators of [Mender](https://mender.io/). This project is currently under construction, with the
primary goal of enhancing the original work while integrating it more closely with Northern.tech's
suite of products.

-------------------------------------------------------------------------------

![Mender logo](https://github.com/mendersoftware/mender/raw/master/mender_logo.png)

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

## Get started

This guide is based on our Zephyr reference application [mender-mcu-integration](https://github.com/mendersoftware/mender-mcu-integration).
The reference application is intended to be used as a reference and a demonstration of how to
use `mender-mcu` as a Zephyr module. We therefore recommend that you start with this to
familiarize yourself with the API and how we set it up.

The policy is that the reference application's `main` branch will follow the latest stable branch of `mender-mcu`
(this repository).

In the `mender-mcu-integration` repository you will find:
* A reference `west` workspace for Zephyr OS builds, including `CMake` and `KConfig` configurations.
* Sample application for how to use `mender-mcu` APIs.
* A list of boards that we have so far tested.

We recommend starting there to understand how we have designed our solution and then coming back
here for more in-depth information.

### Compatibility
| Zephyr OS version |
|-------------------|
| v3.7.0            |

### Boards
The reference board for `mender-mcu` is the [ESP32-S3-DevKitC](https://docs.zephyrproject.org/latest/boards/espressif/esp32s3_devkitc/doc/index.html).

### Setting up a West project with `mender-mcu` as a Zephyr module
See the [Zephyr documentation](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) for more information
on getting started with Zephyr.

In order to use `mender-mcu` as a Zephyr [module](https://docs.zephyrproject.org/latest/develop/modules.html#modules-external-projects)
in a [West project](https://docs.zephyrproject.org/latest/develop/west/basics.html#west-workspace), you will
need to add `mender-mcu` to your project's west manifest:

```yaml
manifest:
  projects:
    - name: mender-mcu
      url: https://github.com/mendersoftware/mender-mcu
      revision: main
      path: modules/mender-mcu
      import: true
```
If you already have a west workspace, you can simply add `mender-mcu` with the following command
inside the workspace after adding the project to the manifest:
```
west update
```
If you're starting from scratch, you can initialize a new workspace based on the manifest like so:
```
west init workspace --manifest-url https://url/to/repository-containing-manifest
cd workspace && west update
```

### Configuring the client
Zephyr provides [tools](https://docs.zephyrproject.org/latest/build/kconfig/menuconfig.html) for configuring
projects, which are used to set Kconfig options. These options are used by Zephyr modules to configure their behavior.

The options for configuring `mender-mcu` are found in the menuconfig under `Modules -> mender-mcu`,
and are prefixed with `MENDER_`.

You can use either `west build -t menuconfig` or `west build -t guiconfig` to open
the configuration menu.

The following option **must** be set in any configuration:
* `MENDER_SERVER_TENANT_TOKEN` which is a token that identifies which tenant a device belongs to.

The most common options to modify are:
* `MENDER_SERVER_HOST`
* `MENDER_CLIENT_UPDATE_POLL_INTERVAL`
* `MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL`

See descriptions of the options in the menuconfig for more information.

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

* User Provided Keys. The client can be configured to use a provided a keypair. If set to
`NULL`, the client will auto-generate its own keypair using ECDSA.

### Update Modules API

The Update Module API is exposed in [mender-update-module.h](include/mender-update-module.h).

Mender MCU models the Update Modules API which we have been using in the regular Mender client for
years. Refer to the [Update Modules chapter in Mender
Docs](https://docs.mender.io/artifact-creation/create-a-custom-update-module) for an introduction.
In Mender MCU, the modules are not "executables" but rather rather a custom C function that is
integrated with the client to handle each type of update.

#### `zephyr-image` Update Module

We provide the `zephyr-image` Update Module, which implements the update process for a Zephyr OS
update integrated with MCUboot. Its [source code](core/src/mender-zephyr-image-update-module.c)
can be inspected for inspiration and a better understanding of the expected behavior of each state.

To use the `zephyr-image` Update Module, you need a board that supports
MCUboot. The following link will filter the officially supported boards that also support MCUboot:
* [Zephyr Project supported boards with MCU boot](https://docs.zephyrproject.org/latest/gsearch.html?q=MCUboot&check_keywords=yes&area=default#gsc.tab=0&gsc.q=MCUboot&gsc.ref=more%3Aboards&gsc.sort=)

#### Update Modules State Machine

As stated above, an Update Module for Mender MCU is set of customizable C functions. Concretely,
once created, all Update Modules are identified by a C struct. The most important part of
the struct is the array of callbacks, one to be called for each state.

See [the state machine workflow
diagram](https://docs.mender.io/artifact-creation/create-a-custom-update-module#the-state-machine-workflow)
to learn about the flow between each state. An Update Module does not need to implement all of them,
only the ones that are relevant for a particular type of update.

After writing the code, you need to register the Update Module into the Mender MCU. See the register
update module function in [`mender-client.h`](include/mender-client.h).


### Network

See this [example](https://github.com/mendersoftware/mender-mcu-integration/blob/main/src/utils/netup.c) from mender-mcu-integration for a demo.
This implementation uses Zephyr's native networking APIs, see [Zephyr's Networking Guide](https://docs.zephyrproject.org/latest/connectivity/networking/index.html).

### Certificates
See this [example](https://github.com/mendersoftware/mender-mcu-integration/blob/main/src/utils/certs.c) from mender-mcu-integration for a demo.

The client expects the users to add the certificates using `tls_credentials_add`. See the
[TLS credentials management](https://docs.zephyrproject.org/latest/doxygen/html/group__tls__credentials.html)
documentation for more information.

The `mender-mcu` client can take up to two certificates; typically one for the Server API calls, and
one for downloading Mender Artifacts from the Server storage. The latter is optional.

Example of how to add certificates to the client:

```cmake
generate_inc_file_for_target(app
    "path/to/certificates/Certificate1.cer"
    "${ZEPHYR_BINARY_DIR}/include/generated/Cerficiate1.cer.inc"
)
```
[`generate_inc_file_for_target`](https://github.com/zephyrproject-rtos/zephyr/blob/bc42004d1be40d9b5bec2d3e8c600780b644ff6e/cmake/modules/extensions.cmake#L703)
is a Zephyr CMake extension.

The certificates should be guarded by the `CONFIG_NET_SOCKETS_SOCKOPT_TLS` option,

Use `CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_SECONDARY_ENABLED` to check if a secondary certificate is enabled.

The API for adding the certificates is provided by Zephyr, and can be used by including
`zephyr/include/net/tls_credentials.h`

You can add the certificate by calling `tls_credential_add` with the following arguments:
* `tag` - The tag of the certificate - configured by setting either:
    * `CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_PRIMARY` - The tag for the primary certificate
    * `CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_SECONDARY` - The tag for the secondary certificate
* `type` - The type of the certificate - should be `TLS_CREDENTIAL_CA_CERTIFICATE`
* `data` - The certificate data - should be an array of unsigned characters
* `len` - The length of the certificate data - should be the size of the array of unsigned characters

Example:
```c
#include <zephyr/net/tls_credentials.h>

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
static const unsigned char ca_certificate_one[] = {
#include "Certificate1.cer.inc"
};
#endif
int add_cert(void) {
    //...
    ret = tls_credential_add(CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_PRIMARY, TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate_one, sizeof(ca_certificate_one));
    //...
}
```

### Starting the client
See this [example](https://github.com/mendersoftware/mender-mcu-integration/blob/main/src/main.c) from mender-mcu-integration for a demo.

#### Initializing the client
Before intializing the client, you must set up the network connection, certificates, and an Update Module.

You must also define two structs:

`mender_client_config_t` with the fields defined in [mender-client.h](include/mender-client.h).
* The `device_type` can be set to `NULL`, as it is defined at build time

and

`mender_client_callbacks_t` with the callbacks defined in [mender-client.h](include/mender-client.h).

See [The Mender client API ](#the-mender-client-api).

After implementing the necessary callbacks and creating the structs,
the client can be initialized by calling `mender_client_init`, which
is defined in [mender-client.h](include/mender-client.h):

Example:
```c
mender_client_init(&mender_client_config, &mender_client_callbacks));
```

#### Registering the Update Module
As mentioned in [Update Modules API](#update-modules-api), you must also register one or more
Update Modules. Without an Update Module, the client can run and report inventory, but it will
not be able to perform any updates.

Registering `zephyr-image` Update Module (compiled in by default):
```c
mender_zephyr_image_register_update_module());
```

#### Enabling Inventory
Inventory is enabled/disabled by setting the `MENDER_CLIENT_INVENTORY` option.

To use inventory, you will need a `mender_keystore_t` struct, which is defined in [mender-client.h](include/mender-client.h).
This struct contains the inventory of the client, and is enabled in the code by calling `mender_inventory_set`.

Example:
```c
mender_keystore_t inventory[] = { { .name = "demo", .value = "demo" }, { .name = "foo", .value = "bar" }, { .name = NULL, .value = NULL } };
mender_inventory_set(inventory));
```

#### Activating the Client
Finally, you can activate the client by calling `mender_client_activate`:
```c
mender_client_activate();
```
After the client is activated, it will run on a workqueue thread, either a dedicated one
(default) or the system one (configurable with the options starting with `CONFIG_SYSTEM_WORKQUEUE_`).
From this thread, the client will regularly poll for updates and submit inventory.

### Building the client

See the [building section](https://github.com/mendersoftware/mender-mcu-integration?tab=readme-ov-file#building-the-zephyr-project-mender-reference-app)
in mender-mcu-integration for a list of the boards that we have tested, and for examples
on how to build for them.

### Creating a Mender Artifact

NOTE: Compression of artifacts is **not** supported, which is why we use `--compression none`

After building the client, you can create a [Mender Artifact](https://docs.mender.io/overview/artifact).

The update module must correspond with one of the ones registered during initialization of the client.
The device type must match the one set at build time - if you're unsure what this is, you can
check the value of `MENDER_DEVICE_TYPE` in the menuconfig, by default it uses Zephyr's `BOARD`.

The Artifact Name is arbitrary, but should be unique.

```bash
UPDATE_MODULE=<update_module>
ARTIFACT_NAME=<artifact_name>
DEVICE_TYPE=<device_type>

mender-artifact write module-image \
  --type $UPDATE_MODULE \
  --file build/zephyr/zephyr.signed.bin \
  --artifact-name $ARTIFACT_NAME \
  --device-type $DEVICE_TYPE \
  --compression none
```
### Deployment
After creating the Artifact, you can upload it to the Mender Server and deploy it to your device.

See the documentation on [deployments](https://docs.mender.io/overview/deployment#deployment) for more information.

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
