---
## 0.10.0 - 2025-08-27


### Bug fixes


- *(build)* Set default value for secondary CA cert to false
([MEN-8351](https://northerntech.atlassian.net/browse/MEN-8351)) ([aca8e5d](https://github.com/mendersoftware/mender-mcu/commit/aca8e5d4788aa4cb428220e56914bb17db8f29c7))  by @lluiscampos


  The secondary CA cert is really optional, as a custom Mender Server
  could use the same domain for both API calls and Artifacts storage.
  
  Set `MENDER_NET_CA_CERTIFICATE_TAG_SECONDARY_ENABLED` default to `n` and
  instead select it when selecting hosted Mender option(s).





### Documentation


- Document how to skip TLS peer verification
([MEN-8351](https://northerntech.atlassian.net/browse/MEN-8351)) ([3b5d1fc](https://github.com/mendersoftware/mender-mcu/commit/3b5d1fcd62ae156a7914efb91fcfb37e53a383e0))  by @lluiscampos




### Features


- Add backup root cert to Zephyr certs chain
([MEN-8494](https://northerntech.atlassian.net/browse/MEN-8494)) ([5e061d5](https://github.com/mendersoftware/mender-mcu/commit/5e061d58e0d5cb42b2adb95747b6caa245f64e3f))  by @elkoniu


  For disaster recovery and emergency having single certificate is risky.
  This change introduces 2nd root certificate to be used on the platform.
- Support Zephyr 4.2.0
([MEN-8638](https://northerntech.atlassian.net/browse/MEN-8638)) ([2d8e634](https://github.com/mendersoftware/mender-mcu/commit/2d8e6341a2e3e83c873c96c9d6f29b9ce8832eb7))  by @danielskinstad


  * replace deprecated swap mode option
  From https://docs.zephyrproject.org/latest/releases/migration-guide-4.1.html:
  ```
  The Kconfig ``SB_CONFIG_MCUBOOT_MODE_SWAP_WITHOUT_SCRATCH`` has been deprecated and replaced
  with ``SB_CONFIG_MCUBOOT_MODE_SWAP_USING_MOVE``, applications should be updated to select this
  new symbol if they were selecting the old symbol.
  ```
  
  Note that this will still allow us to build with older versions, as the
  MCUboot options set in mender-mcu's Kconfig are merely there for verbosity
  
  * return int in response callbacks
  This is needed in order to use Zephyr 4.2.0
  
  From https://docs.zephyrproject.org/latest/releases/migration-guide-4.2.html:
  ```
  The http_response_cb_t HTTP client response callback signature has changed.
  The callback function now returns int instead of void. This allows the
  application to abort the HTTP connection. Existing applications need to
  update their response callback implementations. To retain current behavior,
  simply return 0 from the callback.
  ```
  
  In order to not break backwards compatibility we use Zephyr's `ZEPHYR_VERSION`
  and `ZEPHYR_VERSION_CODE` to define macros that return void on versions
  below 4.2.0 and int on newer versions.






## 0.9.0 - 2025-04-11

* Preview of Mender MCU

---
