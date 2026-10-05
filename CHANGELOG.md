## [v5.0.0]

### Added
- Initialize `wazuh-indexer-alerting` repository [(#1)](https://github.com/wazuh/wazuh-indexer-alerting/issues/1)
- Compatibility with OpenSearch 3.6.0 [(#4)](https://github.com/wazuh/wazuh-indexer-alerting/issues/4)
- Add a dedicated active response monitor type [(#8)](https://github.com/wazuh/wazuh-indexer-alerting/issues/8)
- Add a configurable limit on the number of monitors (`plugins.alerting.monitor.max_monitors`) [(#1276)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276) [(#1420)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1420)
- (operational) Add the `--set-as-main` flag to the repository bumper [(#3)](https://github.com/wazuh/wazuh-indexer-alerting/issues/3)
- (operational) Add revert support to the repository bumper workflow [(#19)](https://github.com/wazuh/wazuh-indexer-alerting/issues/19) [(#81)](https://github.com/wazuh/wazuh-indexer-alerting/issues/81)
- (operational) Add reporting of skipped bumps to the repository bumper workflow [(#125)](https://github.com/wazuh/wazuh-indexer-alerting/issues/125)

### Changed
- Disable alert history, finding history and comments by default [(#1274)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1274)
- Improve doc-level monitor performance by not forcing a findings index refresh per batch [(#1683)](https://github.com/wazuh/wazuh-indexer/issues/1683)
- Reduce log noise from monitor creation and from queries over unmapped fields [(#7)](https://github.com/wazuh/wazuh-indexer-alerting/issues/7)
- (operational) Share build artifacts between workflow jobs through the Maven cache [(#1443)](https://github.com/wazuh/wazuh-indexer/issues/1443)
- (operational) Rename the `build.revision` build argument to `revision` [(#1439)](https://github.com/wazuh/wazuh-indexer/issues/1439)
- (operational) Resolve the plugin build version from `VERSION.json` [(#1595)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1595)
- (operational) Update CodeQL configuration [(#1497)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1497)

### Removed

-

### Fixed
- Fix doc-level monitors skipping documents when search backpressure cancels their percolate search [(#1876)](https://github.com/wazuh/wazuh-indexer/issues/1876)
- Fix rules over a field the source index does not map being silently dropped [(#1518)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1518)
- Fix one failing finding dropping the rest of its batch before it reaches Security Analytics [(#168)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/168)
- Fix a memory leak in doc-level monitors that exhausted the Java heap [(#1746)](https://github.com/wazuh/wazuh-indexer/issues/1746)
- Fix errors from unresolved query index aliases and lock acquisition races during monitor runs [(#1730)](https://github.com/wazuh/wazuh-indexer/issues/1730) [(#1731)](https://github.com/wazuh/wazuh-indexer/issues/1731)
- Fix node restarts being logged as errors and workflow alert failures being logged twice [(#1770)](https://github.com/wazuh/wazuh-indexer/issues/1770) [(#1867)](https://github.com/wazuh/wazuh-indexer/issues/1867)
- Fix SLF4J "no provider" warnings at startup [(#1577)](https://github.com/wazuh/wazuh-indexer/issues/1577)
- (operational) Fix package generation failing when a revision other than `0` is requested [(#1430)](https://github.com/wazuh/wazuh-indexer/issues/1430)
- (operational) Fix the repository bumper `tag` input defaulting to `true` [(#1765)](https://github.com/wazuh/wazuh-indexer/issues/1765)

## Prior versions
- []()
