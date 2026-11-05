# Changelog

## [0.3.0](https://github.com/contriboss/boltwire/compare/v0.2.0...v0.3.0) (2026-11-05)


### Features

* **pool:** acquire timeout and close() ([5798cfd](https://github.com/contriboss/boltwire/commit/5798cfdda3a516d77e434e99388be45566270c84))
* **tls:** custom root stores and certificate pinning ([0717cfc](https://github.com/contriboss/boltwire/commit/0717cfcda4bd5a2c33127bdcba9b10463bce7d06))


### Bug Fixes

* **connection:** keep sessions in sync when a query is cancelled ([8787da2](https://github.com/contriboss/boltwire/commit/8787da24c117a9e939eb4d5f69d8af5c37925545))
* **pool:** fail fast on permanent connect errors ([7cf79c7](https://github.com/contriboss/boltwire/commit/7cf79c789912193666b40636caedb2f840888569))
* **pool:** never drop returned connections under contention ([2862d02](https://github.com/contriboss/boltwire/commit/2862d0203c72944d1dde9d8eaf7d9851c3ce1fb1))
* **tls:** build the rustls config with ring explicitly ([95fcccd](https://github.com/contriboss/boltwire/commit/95fcccdf3cd0d6b81bfc32aef415c269b31fb168))
* **uri:** parse IPv6 routing addresses for the TLS server name ([9cf3a0d](https://github.com/contriboss/boltwire/commit/9cf3a0d2912d057401015562e049b9c2c83ef6c7))


### Performance

* **connection:** pipeline RUN with its first PULL ([f124a5a](https://github.com/contriboss/boltwire/commit/f124a5a8dd9623422d5bc03cebc0474e6d74b401))


### Documentation

* **readme:** pool acquire timeout, close() and cancellation safety ([b695947](https://github.com/contriboss/boltwire/commit/b695947e8ae74669fbc932c88fdd7a1cf7aa0183))

## [0.2.0](https://github.com/contriboss/boltwire/compare/v0.1.0...v0.2.0) (2026-09-14)


### Features

* use Cow&lt;'static&gt; for BoltValue strings and bytes ([1bc7e44](https://github.com/contriboss/boltwire/commit/1bc7e44842def197713f9173943c82364a9a39c4))


### Refactors

* move inline tests to src/*/test.rs, exclude from package ([801d9eb](https://github.com/contriboss/boltwire/commit/801d9eb98543a1b0d968e67c4e06a5c4f2e0be23))
