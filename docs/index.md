# Azure Perimeter Mod

Run security controls across all your Azure subscriptions to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more.

<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-azure-perimeter/main/docs/images/azure_perimeter_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-azure-perimeter/main/docs/images/azure_perimeter_network_access_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-azure-perimeter/main/docs/images/azure_perimeter_public_access_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/steampipe-mod-azure-perimeter/main/docs/images/azure_perimeter_network_access_console.png" width="50%" type="thumbnail"/>

## Documentation

- **[Benchmarks and controls →](https://hub.powerpipe.io/mods/turbot/azure_perimeter/controls)**
- **[Named queries →](https://hub.powerpipe.io/mods/turbot/azure_perimeter/queries)**

## Getting Started

### Installation

Install Powerpipe (https://powerpipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/powerpipe
```

This mod also requires [Steampipe](https://steampipe.io) with the [Azure plugin](https://hub.steampipe.io/plugins/turbot/azure) as the data source. Install Steampipe (https://steampipe.io/downloads), or use Brew:

```sh
brew install turbot/tap/steampipe
steampipe plugin install azure
```

Steampipe will automatically use your default Azure credentials. Optionally, you can [setup multiple subscriptions](https://hub.steampipe.io/plugins/turbot/azure#multi-subscription-connections) or [customize Azure credentials](https://hub.steampipe.io/plugins/turbot/azure#configuring-azure-credentials).

Finally, install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod init
powerpipe mod install github.com/turbot/steampipe-mod-azure-perimeter
```

### Browsing Dashboards

Start Steampipe as the data source:

```sh
steampipe service start
```

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Checks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run azure_perimeter.benchmark.network_access
```

Run a specific control:

```sh
powerpipe control run azure_perimeter.control.network_security_group_restrict_ingress_common_ports_all
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).

### Common and Tag Dimensions

The benchmark queries use common properties (like `connection_name`, `resource_group`, `region`, `subscription` and `subscription_id`) and tags that are defined in the form of a default list of strings in the `variables.sp` file. These properties can be overwritten in several ways:

It's easiest to setup your vars file, starting with the sample:

```sh
cp powerpipe.ppvars.example powerpipe.ppvars
vi powerpipe.ppvars
```

Alternatively you can pass variables on the command line:

```sh
powerpipe benchmark run azure_perimeter.benchmark.public_access_settings --var 'azure_perimeter.common_dimensions=["subscription_id", "connection_name", "resource_group"]'
```

Or through environment variables:

```sh
export PP_VAR_common_dimensions='["subscription_id", "connection_name", "resource_group"]'
export PP_VAR_tag_dimensions='["Environment", "Owner"]'
powerpipe control run azure_perimeter.control.network_security_group_restrict_ingress_common_ports_all
```

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Steampipe](https://steampipe.io) and [Powerpipe](https://powerpipe.io) are products produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). They are distributed under our commercial terms. Others are allowed to make their own distribution of the software, but cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #powerpipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:

- [Powerpipe](https://github.com/turbot/powerpipe/labels/help%20wanted)
- [Azure Perimeter Mod](https://github.com/turbot/steampipe-mod-azure-perimeter/labels/help%20wanted)
