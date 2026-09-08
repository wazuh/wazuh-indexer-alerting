## [v5.0.0]

### Added

- Initialize `wazuh-indexer-alerting` repository [(#1)](https://github.com/wazuh/wazuh-indexer-alerting/issues/1) [(#3)](https://github.com/wazuh/wazuh-indexer-alerting/issues/3)
- Support Revert bump functionality in wazuh-indexer-alerting [(#19)](https://github.com/wazuh/wazuh-indexer-alerting/issues/19)
- Implement dedicated monitor for Active Response [(#8)](https://github.com/wazuh/wazuh-indexer-alerting/issues/8)
- Configurable resource creation limits [(#1276)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276)

### Changed

- Alerting logs review [(#7)](https://github.com/wazuh/wazuh-indexer-alerting/issues/7)

### Removed

-

### Fixed
- RCA: missing findings [(#168)](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/168)
- SLF4J "no provider" warnings during startup [(#1577)](https://github.com/wazuh/wazuh-indexer/issues/1577)
- java.lang.OutOfMemoryError: Java heap space in Soak agent tests [(#1746)](https://github.com/wazuh/wazuh-indexer/issues/1746)
- Improve logs based on Analysis [(#1770)](https://github.com/wazuh/wazuh-indexer/issues/1770)
- Fixed unresolved write-index alias errors in document-level monitors [(#1731)](https://github.com/wazuh/wazuh-indexer/issues/1731) [(#1730)](https://github.com/wazuh/wazuh-indexer/issues/1730)
- Fix noisy error logs and workflow failures caused by lock acquisition race conditions [(#1730)](https://github.com/wazuh/wazuh-indexer/issues/1730)
- Recognise an orderly node shutdown in the remaining alerting error paths instead of logging it as a failure [(#1867)](https://github.com/wazuh/wazuh-indexer/issues/1867) [(#1788)](https://github.com/wazuh/wazuh-indexer/issues/1788)
- Fix rules over a field that the source index does not map being silently dropped, which left missing-field detection unable to ever match [(#1518)](https://github.com/wazuh/wazuh-indexer-plugins/issues/1518)

## Prior versions
- []()
