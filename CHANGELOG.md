---
## 0.10.0 - 2026-02-10


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





- Send tier in authentication request
([MEN-8559](https://northerntech.atlassian.net/browse/MEN-8559)) ([ecfa717](https://github.com/mendersoftware/mender-mcu/commit/ecfa71738f308f6006cc444c02181e162c2f7d2b))  by @danielskinstad





  Add device tier support to authentication requests. The client now
  sends a 'tier' parameter in authentication requests, supporting "standard"
  (default) and "micro" tiers. The tier is configurable via Kconfig or
  through the client config struct before initialization, which will take
  precedence over the Kconfig option.
- Default device tier to "micro"
 ([6fb81d2](https://github.com/mendersoftware/mender-mcu/commit/6fb81d2a084c7fb6651b310ef9ae3be48e96386b))  by @danielskinstad





  Set the default device tier to "micro" rather
  than "standard".
- Change default intervals for update polling and inventory refresh to 7 days
([MEN-9038](https://northerntech.atlassian.net/browse/MEN-9038)) ([4e987ba](https://github.com/mendersoftware/mender-mcu/commit/4e987ba11af32eb8fbda238bafd88ca54f631a37))  by @michalkopczan





- Produce a warning during build if configured intervals are too short
([MEN-9038](https://northerntech.atlassian.net/browse/MEN-9038)) ([32a2340](https://github.com/mendersoftware/mender-mcu/commit/32a23400d1107d80494e51bbda012263a270cab6))  by @michalkopczan





  When configured update polling and inventory refresh intervals are
  shorter than the minimum allowed for micro tier, produce a warning during build.
- Handle rate limits with value provided by server
([MEN-8849](https://northerntech.atlassian.net/browse/MEN-8849)) ([98b4cbc](https://github.com/mendersoftware/mender-mcu/commit/98b4cbcd7b49464ee38a05d58d6eca9ee04261ae))  by @danielskinstad





  Added support for reading the Retry-After header on HTTP 429 errors.
  When a 429 error is detected, parse the Retry-After header value and use
  it to schedule the next HTTP request instead of using the backoff mechanism.




### Build


- Support warning/failing on artifact sizes
([MEN-8584](https://northerntech.atlassian.net/browse/MEN-8584)) ([330f72e](https://github.com/mendersoftware/mender-mcu/commit/330f72e85371d5af76bc73b0222bb27315303b60))  by @danielskinstad





  Add support for specifying size limits for Mender
  Artifacts during a build. This uses the feature implemented in
  mender-artifact 4.2.0. The limits can be configured through the Kconfig,
      or by enabling `MENDER_ARTIFACT_SIZE_LIMITS` and setting
      `MENDER_ARTIFACT_WARN_SIZE` and or `MENDER_ARTIFACT_MAX_SIZE`.
- Fix misc typos in Kconfig
 ([aefe5cc](https://github.com/mendersoftware/mender-mcu/commit/aefe5ccfe4012ac308eb38db480e89d0330640a1))  by @lluiscampos








## 0.9.0 - 2025-04-11

* Preview of Mender MCU

---
