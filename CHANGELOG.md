## [v5.0.0]

### Added

| Issue | Comment |
|-------|---------|
| [#1](https://github.com/wazuh/wazuh-indexer-alerting/issues/1) | Initialize `wazuh-indexer-alerting` repository |
| [#4](https://github.com/wazuh/wazuh-indexer-alerting/issues/4) | Compatibility with OpenSearch 3.6.0 |
| [#8](https://github.com/wazuh/wazuh-indexer-alerting/issues/8) | Add a dedicated active response monitor type |
| [#1276](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276) [#1420](https://github.com/wazuh/wazuh-indexer-plugins/issues/1420) | Add a configurable limit on the number of monitors (`plugins.alerting.monitor.max_monitors`) |

### Changed

| Issue | Comment |
|-------|---------|
| [#1274](https://github.com/wazuh/wazuh-indexer-plugins/issues/1274) | Disable alert history, finding history and comments by default |
| [#1683](https://github.com/wazuh/wazuh-indexer/issues/1683) | Improve doc-level monitor performance by not forcing a findings index refresh per batch |
| [#7](https://github.com/wazuh/wazuh-indexer-alerting/issues/7) | Reduce log noise from monitor creation and from queries over unmapped fields |

### Removed

| Issue | Comment |
|-------|---------|

### Fixed

| Issue | Comment |
|-------|---------|
| [#1518](https://github.com/wazuh/wazuh-indexer-plugins/issues/1518) | Fix rules over a field the source index does not map being silently dropped |
| [#1746](https://github.com/wazuh/wazuh-indexer/issues/1746) | Fix a memory leak in doc-level monitors that exhausted the Java heap |
| [#1730](https://github.com/wazuh/wazuh-indexer/issues/1730) [#1731](https://github.com/wazuh/wazuh-indexer/issues/1731) | Fix errors from unresolved query index aliases and lock acquisition races during monitor runs |
| [#1770](https://github.com/wazuh/wazuh-indexer/issues/1770) [#1867](https://github.com/wazuh/wazuh-indexer/issues/1867) [#2003](https://github.com/wazuh/wazuh-indexer/issues/2003) | Fix node restarts being logged as errors and workflow alert failures being logged twice |
| [#1577](https://github.com/wazuh/wazuh-indexer/issues/1577) | Fix SLF4J "no provider" warnings at startup |
| [#1968](https://github.com/wazuh/wazuh-indexer/issues/1968) | Fix doc-level monitor runs being abandoned, or losing documents, when their detector is updated while they run |

## Prior versions
