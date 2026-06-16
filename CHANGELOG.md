# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [v5.0.0]

### Added

- Repo initialization [(#2)](https://github.com/wazuh/wazuh-indexer-alerting/pull/2)
- Add Support Revert Bump Functionality [(#23)](https://github.com/wazuh/wazuh-indexer-alerting/pull/23)
- Implement dedicated monitor for Active Response [(#66)](https://github.com/wazuh/wazuh-indexer-alerting/pull/66)

### Dependencies

-

### Changed

- Reduce alerting plugin log verbosity [(#25)](https://github.com/wazuh/wazuh-indexer-alerting/pull/25)

### Deprecated

-

### Removed

-

### Fixed
- Fix publish-findings forEach try/catch dropping rest of batch on first error [(#49)](https://github.com/wazuh/wazuh-indexer-alerting/pull/49)
- Fix SLF4J startup warning by adding Log4j2 provider [(#74)](https://github.com/wazuh/wazuh-indexer-alerting/pull/74)

  

### Security


## Prior versions

This is the initial release of Wazuh Indexer 5.0, so there are no prior 5.x versions. Previous releases can be found under the 4.x branch.

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-alerting/compare/f4b9eb4fb9a698ff40648d4adac808c83d9d4cf7...main
