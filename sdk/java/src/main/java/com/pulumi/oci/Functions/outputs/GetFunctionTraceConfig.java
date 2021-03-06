// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetFunctionTraceConfig {
    /**
     * @return Define if tracing is enabled for the resource.
     * 
     */
    private final Boolean isEnabled;

    @CustomType.Constructor
    private GetFunctionTraceConfig(@CustomType.Parameter("isEnabled") Boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    /**
     * @return Define if tracing is enabled for the resource.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFunctionTraceConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean isEnabled;

        public Builder() {
    	      // Empty
        }

        public Builder(GetFunctionTraceConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
        }

        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }        public GetFunctionTraceConfig build() {
            return new GetFunctionTraceConfig(isEnabled);
        }
    }
}
