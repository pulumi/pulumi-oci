// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagementAgentPluginCountItemDimension {
    /**
     * @return Management Agent Plugin Display Name
     * 
     */
    private String pluginDisplayName;
    /**
     * @return Management Agent Plugin Name
     * 
     */
    private String pluginName;

    private GetManagementAgentPluginCountItemDimension() {}
    /**
     * @return Management Agent Plugin Display Name
     * 
     */
    public String pluginDisplayName() {
        return this.pluginDisplayName;
    }
    /**
     * @return Management Agent Plugin Name
     * 
     */
    public String pluginName() {
        return this.pluginName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentPluginCountItemDimension defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String pluginDisplayName;
        private String pluginName;
        public Builder() {}
        public Builder(GetManagementAgentPluginCountItemDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.pluginDisplayName = defaults.pluginDisplayName;
    	      this.pluginName = defaults.pluginName;
        }

        @CustomType.Setter
        public Builder pluginDisplayName(String pluginDisplayName) {
            if (pluginDisplayName == null) {
              throw new MissingRequiredPropertyException("GetManagementAgentPluginCountItemDimension", "pluginDisplayName");
            }
            this.pluginDisplayName = pluginDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder pluginName(String pluginName) {
            if (pluginName == null) {
              throw new MissingRequiredPropertyException("GetManagementAgentPluginCountItemDimension", "pluginName");
            }
            this.pluginName = pluginName;
            return this;
        }
        public GetManagementAgentPluginCountItemDimension build() {
            final var _resultValue = new GetManagementAgentPluginCountItemDimension();
            _resultValue.pluginDisplayName = pluginDisplayName;
            _resultValue.pluginName = pluginName;
            return _resultValue;
        }
    }
}
