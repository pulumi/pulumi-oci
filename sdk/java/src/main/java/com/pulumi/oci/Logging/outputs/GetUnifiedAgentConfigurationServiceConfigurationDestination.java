// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetUnifiedAgentConfigurationServiceConfigurationDestination {
    /**
     * @return The OCID of the resource.
     * 
     */
    private final String logObjectId;

    @CustomType.Constructor
    private GetUnifiedAgentConfigurationServiceConfigurationDestination(@CustomType.Parameter("logObjectId") String logObjectId) {
        this.logObjectId = logObjectId;
    }

    /**
     * @return The OCID of the resource.
     * 
     */
    public String logObjectId() {
        return this.logObjectId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUnifiedAgentConfigurationServiceConfigurationDestination defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String logObjectId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetUnifiedAgentConfigurationServiceConfigurationDestination defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.logObjectId = defaults.logObjectId;
        }

        public Builder logObjectId(String logObjectId) {
            this.logObjectId = Objects.requireNonNull(logObjectId);
            return this;
        }        public GetUnifiedAgentConfigurationServiceConfigurationDestination build() {
            return new GetUnifiedAgentConfigurationServiceConfigurationDestination(logObjectId);
        }
    }
}
