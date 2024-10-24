// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfigPluginsConfig;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfig {
    /**
     * @return Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     * To get a list of available plugins, use the [ListInstanceagentAvailablePlugins](https://docs.cloud.oracle.com/iaas/api/#/en/instanceagent/20180530/Plugin/ListInstanceagentAvailablePlugins) operation in the Oracle Cloud Agent API. For more information about the available plugins, see [Managing Plugins with Oracle Cloud Agent](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/manage-plugins.htm).
     * 
     */
    private @Nullable Boolean areAllPluginsDisabled;
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
     * 
     * These are the management plugins: OS Management Service Agent and Compute Instance Run Command.
     * 
     * The management plugins are controlled by this parameter and by the per-plugin configuration in the `pluginsConfig` object.
     * * If `isManagementDisabled` is true, all of the management plugins are disabled, regardless of the per-plugin configuration.
     * * If `isManagementDisabled` is false, all of the management plugins are enabled. You can optionally disable individual management plugins by providing a value in the `pluginsConfig` object.
     * 
     */
    private @Nullable Boolean isManagementDisabled;
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
     * 
     * These are the monitoring plugins: Compute Instance Monitoring and Custom Logs Monitoring.
     * 
     * The monitoring plugins are controlled by this parameter and by the per-plugin configuration in the `pluginsConfig` object.
     * * If `isMonitoringDisabled` is true, all of the monitoring plugins are disabled, regardless of the per-plugin configuration.
     * * If `isMonitoringDisabled` is false, all of the monitoring plugins are enabled. You can optionally disable individual monitoring plugins by providing a value in the `pluginsConfig` object.
     * 
     */
    private @Nullable Boolean isMonitoringDisabled;
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    private @Nullable List<InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfigPluginsConfig> pluginsConfigs;

    private InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfig() {}
    /**
     * @return Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     * To get a list of available plugins, use the [ListInstanceagentAvailablePlugins](https://docs.cloud.oracle.com/iaas/api/#/en/instanceagent/20180530/Plugin/ListInstanceagentAvailablePlugins) operation in the Oracle Cloud Agent API. For more information about the available plugins, see [Managing Plugins with Oracle Cloud Agent](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/manage-plugins.htm).
     * 
     */
    public Optional<Boolean> areAllPluginsDisabled() {
        return Optional.ofNullable(this.areAllPluginsDisabled);
    }
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
     * 
     * These are the management plugins: OS Management Service Agent and Compute Instance Run Command.
     * 
     * The management plugins are controlled by this parameter and by the per-plugin configuration in the `pluginsConfig` object.
     * * If `isManagementDisabled` is true, all of the management plugins are disabled, regardless of the per-plugin configuration.
     * * If `isManagementDisabled` is false, all of the management plugins are enabled. You can optionally disable individual management plugins by providing a value in the `pluginsConfig` object.
     * 
     */
    public Optional<Boolean> isManagementDisabled() {
        return Optional.ofNullable(this.isManagementDisabled);
    }
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
     * 
     * These are the monitoring plugins: Compute Instance Monitoring and Custom Logs Monitoring.
     * 
     * The monitoring plugins are controlled by this parameter and by the per-plugin configuration in the `pluginsConfig` object.
     * * If `isMonitoringDisabled` is true, all of the monitoring plugins are disabled, regardless of the per-plugin configuration.
     * * If `isMonitoringDisabled` is false, all of the monitoring plugins are enabled. You can optionally disable individual monitoring plugins by providing a value in the `pluginsConfig` object.
     * 
     */
    public Optional<Boolean> isMonitoringDisabled() {
        return Optional.ofNullable(this.isMonitoringDisabled);
    }
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    public List<InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfigPluginsConfig> pluginsConfigs() {
        return this.pluginsConfigs == null ? List.of() : this.pluginsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean areAllPluginsDisabled;
        private @Nullable Boolean isManagementDisabled;
        private @Nullable Boolean isMonitoringDisabled;
        private @Nullable List<InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfigPluginsConfig> pluginsConfigs;
        public Builder() {}
        public Builder(InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areAllPluginsDisabled = defaults.areAllPluginsDisabled;
    	      this.isManagementDisabled = defaults.isManagementDisabled;
    	      this.isMonitoringDisabled = defaults.isMonitoringDisabled;
    	      this.pluginsConfigs = defaults.pluginsConfigs;
        }

        @CustomType.Setter
        public Builder areAllPluginsDisabled(@Nullable Boolean areAllPluginsDisabled) {

            this.areAllPluginsDisabled = areAllPluginsDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder isManagementDisabled(@Nullable Boolean isManagementDisabled) {

            this.isManagementDisabled = isManagementDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder isMonitoringDisabled(@Nullable Boolean isMonitoringDisabled) {

            this.isMonitoringDisabled = isMonitoringDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder pluginsConfigs(@Nullable List<InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfigPluginsConfig> pluginsConfigs) {

            this.pluginsConfigs = pluginsConfigs;
            return this;
        }
        public Builder pluginsConfigs(InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfigPluginsConfig... pluginsConfigs) {
            return pluginsConfigs(List.of(pluginsConfigs));
        }
        public InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfig build() {
            final var _resultValue = new InstanceConfigurationInstanceDetailsOptionLaunchDetailsAgentConfig();
            _resultValue.areAllPluginsDisabled = areAllPluginsDisabled;
            _resultValue.isManagementDisabled = isManagementDisabled;
            _resultValue.isMonitoringDisabled = isMonitoringDisabled;
            _resultValue.pluginsConfigs = pluginsConfigs;
            return _resultValue;
        }
    }
}
