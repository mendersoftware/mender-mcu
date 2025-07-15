---
## 0.10.0 - 2025-07-15


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






## 0.9.0 - 2025-04-11

* Preview of Mender MCU

---
