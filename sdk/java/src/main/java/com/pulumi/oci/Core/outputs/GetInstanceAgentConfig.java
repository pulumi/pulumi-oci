// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceAgentConfigPluginsConfig;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceAgentConfig {
    /**
     * @return Whether Oracle Cloud Agent can run all of the available plugins. This includes the management and monitoring plugins.
     * 
     */
    private final Boolean areAllPluginsDisabled;
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins.
     * 
     */
    private final Boolean isManagementDisabled;
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins.
     * 
     */
    private final Boolean isMonitoringDisabled;
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    private final List<GetInstanceAgentConfigPluginsConfig> pluginsConfigs;

    @CustomType.Constructor
    private GetInstanceAgentConfig(
        @CustomType.Parameter("areAllPluginsDisabled") Boolean areAllPluginsDisabled,
        @CustomType.Parameter("isManagementDisabled") Boolean isManagementDisabled,
        @CustomType.Parameter("isMonitoringDisabled") Boolean isMonitoringDisabled,
        @CustomType.Parameter("pluginsConfigs") List<GetInstanceAgentConfigPluginsConfig> pluginsConfigs) {
        this.areAllPluginsDisabled = areAllPluginsDisabled;
        this.isManagementDisabled = isManagementDisabled;
        this.isMonitoringDisabled = isMonitoringDisabled;
        this.pluginsConfigs = pluginsConfigs;
    }

    /**
     * @return Whether Oracle Cloud Agent can run all of the available plugins. This includes the management and monitoring plugins.
     * 
     */
    public Boolean areAllPluginsDisabled() {
        return this.areAllPluginsDisabled;
    }
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins.
     * 
     */
    public Boolean isManagementDisabled() {
        return this.isManagementDisabled;
    }
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins.
     * 
     */
    public Boolean isMonitoringDisabled() {
        return this.isMonitoringDisabled;
    }
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    public List<GetInstanceAgentConfigPluginsConfig> pluginsConfigs() {
        return this.pluginsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceAgentConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean areAllPluginsDisabled;
        private Boolean isManagementDisabled;
        private Boolean isMonitoringDisabled;
        private List<GetInstanceAgentConfigPluginsConfig> pluginsConfigs;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceAgentConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areAllPluginsDisabled = defaults.areAllPluginsDisabled;
    	      this.isManagementDisabled = defaults.isManagementDisabled;
    	      this.isMonitoringDisabled = defaults.isMonitoringDisabled;
    	      this.pluginsConfigs = defaults.pluginsConfigs;
        }

        public Builder areAllPluginsDisabled(Boolean areAllPluginsDisabled) {
            this.areAllPluginsDisabled = Objects.requireNonNull(areAllPluginsDisabled);
            return this;
        }
        public Builder isManagementDisabled(Boolean isManagementDisabled) {
            this.isManagementDisabled = Objects.requireNonNull(isManagementDisabled);
            return this;
        }
        public Builder isMonitoringDisabled(Boolean isMonitoringDisabled) {
            this.isMonitoringDisabled = Objects.requireNonNull(isMonitoringDisabled);
            return this;
        }
        public Builder pluginsConfigs(List<GetInstanceAgentConfigPluginsConfig> pluginsConfigs) {
            this.pluginsConfigs = Objects.requireNonNull(pluginsConfigs);
            return this;
        }
        public Builder pluginsConfigs(GetInstanceAgentConfigPluginsConfig... pluginsConfigs) {
            return pluginsConfigs(List.of(pluginsConfigs));
        }        public GetInstanceAgentConfig build() {
            return new GetInstanceAgentConfig(areAllPluginsDisabled, isManagementDisabled, isMonitoringDisabled, pluginsConfigs);
        }
    }
}
