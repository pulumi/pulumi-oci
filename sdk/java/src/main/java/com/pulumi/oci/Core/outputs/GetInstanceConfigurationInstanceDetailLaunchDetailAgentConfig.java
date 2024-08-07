// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfigPluginsConfig;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig {
    /**
     * @return Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     */
    private Boolean areAllPluginsDisabled;
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
     * 
     */
    private Boolean isManagementDisabled;
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
     * 
     */
    private Boolean isMonitoringDisabled;
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    private List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfigPluginsConfig> pluginsConfigs;

    private GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig() {}
    /**
     * @return Whether Oracle Cloud Agent can run all the available plugins. This includes the management and monitoring plugins.
     * 
     */
    public Boolean areAllPluginsDisabled() {
        return this.areAllPluginsDisabled;
    }
    /**
     * @return Whether Oracle Cloud Agent can run all the available management plugins. Default value is false (management plugins are enabled).
     * 
     */
    public Boolean isManagementDisabled() {
        return this.isManagementDisabled;
    }
    /**
     * @return Whether Oracle Cloud Agent can gather performance metrics and monitor the instance using the monitoring plugins. Default value is false (monitoring plugins are enabled).
     * 
     */
    public Boolean isMonitoringDisabled() {
        return this.isMonitoringDisabled;
    }
    /**
     * @return The configuration of plugins associated with this instance.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfigPluginsConfig> pluginsConfigs() {
        return this.pluginsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean areAllPluginsDisabled;
        private Boolean isManagementDisabled;
        private Boolean isMonitoringDisabled;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfigPluginsConfig> pluginsConfigs;
        public Builder() {}
        public Builder(GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areAllPluginsDisabled = defaults.areAllPluginsDisabled;
    	      this.isManagementDisabled = defaults.isManagementDisabled;
    	      this.isMonitoringDisabled = defaults.isMonitoringDisabled;
    	      this.pluginsConfigs = defaults.pluginsConfigs;
        }

        @CustomType.Setter
        public Builder areAllPluginsDisabled(Boolean areAllPluginsDisabled) {
            if (areAllPluginsDisabled == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig", "areAllPluginsDisabled");
            }
            this.areAllPluginsDisabled = areAllPluginsDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder isManagementDisabled(Boolean isManagementDisabled) {
            if (isManagementDisabled == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig", "isManagementDisabled");
            }
            this.isManagementDisabled = isManagementDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder isMonitoringDisabled(Boolean isMonitoringDisabled) {
            if (isMonitoringDisabled == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig", "isMonitoringDisabled");
            }
            this.isMonitoringDisabled = isMonitoringDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder pluginsConfigs(List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfigPluginsConfig> pluginsConfigs) {
            if (pluginsConfigs == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig", "pluginsConfigs");
            }
            this.pluginsConfigs = pluginsConfigs;
            return this;
        }
        public Builder pluginsConfigs(GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfigPluginsConfig... pluginsConfigs) {
            return pluginsConfigs(List.of(pluginsConfigs));
        }
        public GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig build() {
            final var _resultValue = new GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig();
            _resultValue.areAllPluginsDisabled = areAllPluginsDisabled;
            _resultValue.isManagementDisabled = isManagementDisabled;
            _resultValue.isMonitoringDisabled = isMonitoringDisabled;
            _resultValue.pluginsConfigs = pluginsConfigs;
            return _resultValue;
        }
    }
}
