// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection {
    /**
     * @return The name key to tag this Grok pattern.
     * 
     */
    private String name;
    /**
     * @return Parameters of the custom filter
     * 
     */
    private Map<String,String> params;

    private GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection() {}
    /**
     * @return The name key to tag this Grok pattern.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Parameters of the custom filter
     * 
     */
    public Map<String,String> params() {
        return this.params;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private Map<String,String> params;
        public Builder() {}
        public Builder(GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.params = defaults.params;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder params(Map<String,String> params) {
            if (params == null) {
              throw new MissingRequiredPropertyException("GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection", "params");
            }
            this.params = params;
            return this;
        }
        public GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection build() {
            final var _resultValue = new GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterCustomSection();
            _resultValue.name = name;
            _resultValue.params = params;
            return _resultValue;
        }
    }
}
