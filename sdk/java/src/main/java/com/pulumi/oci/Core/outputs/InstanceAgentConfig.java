// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.InstanceAgentConfigPluginsConfig;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceAgentConfig {
    /**
     * @return (Updatable) Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     */
    private @Nullable Boolean areAllPluginsDisabled;
    /**
     * @return (Updatable) Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
     * 
     */
    private @Nullable Boolean isManagementDisabled;
    /**
     * @return (Updatable) Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
     * 
     */
    private @Nullable Boolean isMonitoringDisabled;
    /**
     * @return (Updatable) The configuration of plugins associated with this instance.
     * 
     */
    private @Nullable List<InstanceAgentConfigPluginsConfig> pluginsConfigs;

    private InstanceAgentConfig() {}
    /**
     * @return (Updatable) Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     */
    public Optional<Boolean> areAllPluginsDisabled() {
        return Optional.ofNullable(this.areAllPluginsDisabled);
    }
    /**
     * @return (Updatable) Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
     * 
     */
    public Optional<Boolean> isManagementDisabled() {
        return Optional.ofNullable(this.isManagementDisabled);
    }
    /**
     * @return (Updatable) Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
     * 
     */
    public Optional<Boolean> isMonitoringDisabled() {
        return Optional.ofNullable(this.isMonitoringDisabled);
    }
    /**
     * @return (Updatable) The configuration of plugins associated with this instance.
     * 
     */
    public List<InstanceAgentConfigPluginsConfig> pluginsConfigs() {
        return this.pluginsConfigs == null ? List.of() : this.pluginsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceAgentConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean areAllPluginsDisabled;
        private @Nullable Boolean isManagementDisabled;
        private @Nullable Boolean isMonitoringDisabled;
        private @Nullable List<InstanceAgentConfigPluginsConfig> pluginsConfigs;
        public Builder() {}
        public Builder(InstanceAgentConfig defaults) {
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
        public Builder pluginsConfigs(@Nullable List<InstanceAgentConfigPluginsConfig> pluginsConfigs) {
            this.pluginsConfigs = pluginsConfigs;
            return this;
        }
        public Builder pluginsConfigs(InstanceAgentConfigPluginsConfig... pluginsConfigs) {
            return pluginsConfigs(List.of(pluginsConfigs));
        }
        public InstanceAgentConfig build() {
            final var o = new InstanceAgentConfig();
            o.areAllPluginsDisabled = areAllPluginsDisabled;
            o.isManagementDisabled = isManagementDisabled;
            o.isMonitoringDisabled = isMonitoringDisabled;
            o.pluginsConfigs = pluginsConfigs;
            return o;
        }
    }
}