// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceAgentConfigPluginsConfig;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstancesInstanceAgentConfig {
    /**
     * @return Whether Oracle Cloud Agent can run all of the available plugins. This includes the management and monitoring plugins.
     * 
     */
    private Boolean areAllPluginsDisabled;
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins.
     * 
     */
    private Boolean isManagementDisabled;
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins.
     * 
     */
    private Boolean isMonitoringDisabled;
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    private List<GetInstancesInstanceAgentConfigPluginsConfig> pluginsConfigs;

    private GetInstancesInstanceAgentConfig() {}
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
    public List<GetInstancesInstanceAgentConfigPluginsConfig> pluginsConfigs() {
        return this.pluginsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstancesInstanceAgentConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean areAllPluginsDisabled;
        private Boolean isManagementDisabled;
        private Boolean isMonitoringDisabled;
        private List<GetInstancesInstanceAgentConfigPluginsConfig> pluginsConfigs;
        public Builder() {}
        public Builder(GetInstancesInstanceAgentConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areAllPluginsDisabled = defaults.areAllPluginsDisabled;
    	      this.isManagementDisabled = defaults.isManagementDisabled;
    	      this.isMonitoringDisabled = defaults.isMonitoringDisabled;
    	      this.pluginsConfigs = defaults.pluginsConfigs;
        }

        @CustomType.Setter
        public Builder areAllPluginsDisabled(Boolean areAllPluginsDisabled) {
            this.areAllPluginsDisabled = Objects.requireNonNull(areAllPluginsDisabled);
            return this;
        }
        @CustomType.Setter
        public Builder isManagementDisabled(Boolean isManagementDisabled) {
            this.isManagementDisabled = Objects.requireNonNull(isManagementDisabled);
            return this;
        }
        @CustomType.Setter
        public Builder isMonitoringDisabled(Boolean isMonitoringDisabled) {
            this.isMonitoringDisabled = Objects.requireNonNull(isMonitoringDisabled);
            return this;
        }
        @CustomType.Setter
        public Builder pluginsConfigs(List<GetInstancesInstanceAgentConfigPluginsConfig> pluginsConfigs) {
            this.pluginsConfigs = Objects.requireNonNull(pluginsConfigs);
            return this;
        }
        public Builder pluginsConfigs(GetInstancesInstanceAgentConfigPluginsConfig... pluginsConfigs) {
            return pluginsConfigs(List.of(pluginsConfigs));
        }
        public GetInstancesInstanceAgentConfig build() {
            final var o = new GetInstancesInstanceAgentConfig();
            o.areAllPluginsDisabled = areAllPluginsDisabled;
            o.isManagementDisabled = isManagementDisabled;
            o.isMonitoringDisabled = isMonitoringDisabled;
            o.pluginsConfigs = pluginsConfigs;
            return o;
        }
    }
}