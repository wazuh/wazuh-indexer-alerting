<p align="center">
    <img width="640px" src="https://wazuh.com/brand-assets/Wazuh-Logo.svg"/>
</p>

[![Chat](https://img.shields.io/badge/chat-on%20forums-blue)](https://groups.google.com/forum/#!forum/wazuh)
[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack)
[![Documentation](https://img.shields.io/badge/documentation-reference-blue)](https://documentation.wazuh.com)

- [Wazuh Indexer Alerting](#wazuh-indexer-alerting)
- [Project Resources](#project-resources)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Copyright](#copyright)

## Wazuh Indexer Alerting

The **Wazuh Indexer Alerting** enables you to monitor your data and send alert notifications automatically to your
stakeholders. With an intuitive Wazuh Dashboards interface and a powerful API, it is easy to set up, manage, and
monitor your alerts. Craft highly specific alert conditions using Elasticsearch's full query language and scripting
capabilities.

This repository is an open-source fork of the [OpenSearch alerting](https://github.com/opensearch-project/alerting) project, adapted to ensure seamless integration within the Wazuh ecosystem.

### Key Components

The **Wazuh Indexer Alerting** plugin is composed of the following modules:

1. **Alerting Core** (`core/`): Provides foundational functionality for scheduled job execution and coordination.
   - Job scheduling and execution
   - Periodic job sweeping and management
   - Distributed locking mechanisms
   - Common utilities and base classes

2. **Alerting Plugin** (`alerting/`): Main plugin module delivering monitoring and alerting capabilities.
   - **Monitor Management**: Create, read, update, and delete monitoring rules with support for multiple monitor types
   - **Workflow Orchestration**: Chain multiple monitors together for complex alerting workflows
   - **Multi-Level Monitoring**: Support for query-level, document-level, bucket-level, and cluster metrics monitoring
   - **Alert Management**: Comprehensive alert lifecycle management (creation, acknowledgment, resolution)
   - **Destination Integration**: Email accounts, groups, and custom notification destinations

3. **Service Layer**: Core business logic and operations.
   - `MonitorRunnerService`: Executes monitors on schedule
   - `TriggerService`: Evaluates and manages trigger conditions
   - `AlertService`: Manages alert state and lifecycle
   - `DeleteMonitorService`: Handles monitor cleanup and deregistration

4. **REST API & Transport Layer**: API endpoints and inter-node communication.
   - RESTful endpoints for monitor CRUD operations
   - Workflow management endpoints
   - Transport actions for distributed execution
   - Support for both V1 and V2 API versions

5. **SPI (Service Provider Interface)** (`spi/`): Extensibility mechanism for custom monitors.
   - `RemoteMonitorRunnerExtension`: Allows third-party implementations of custom monitor types
   - Enables plugin ecosystem integration

6. **Alert Indices**: Manages alert storage and metadata.
   - Alert indexing and querying
   - Comments and findings tracking
   - Index lifecycle management for alert data

## Project Resources

* [Project Website](https://wazuh.com)
* [Documentation](https://documentation.wazuh.com)
* Need help? Try [Slack](https://wazuh.com/community/join-us-on-slack)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and join in. We welcome bug reports and feature requests through GitHub issues.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md).

## Security

To report a possible vulnerability or security issue, please email us at **security@wazuh.com** or open a report under the Security tab. **PLEASE DO NOT OPEN A PUBLIC ISSUE.**

## License

This project is licensed under the [Apache v2.0 License](LICENSE.txt).

## Copyright

Copyright Wazuh, Inc. (Original code Copyright OpenSearch Contributors). See [NOTICE](NOTICE.txt) for details.
