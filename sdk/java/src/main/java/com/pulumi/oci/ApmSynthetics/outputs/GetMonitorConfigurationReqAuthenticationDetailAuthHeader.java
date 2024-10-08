// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitorConfigurationReqAuthenticationDetailAuthHeader {
    /**
     * @return Name of the header.
     * 
     */
    private String headerName;
    /**
     * @return Value of the header.
     * 
     */
    private String headerValue;

    private GetMonitorConfigurationReqAuthenticationDetailAuthHeader() {}
    /**
     * @return Name of the header.
     * 
     */
    public String headerName() {
        return this.headerName;
    }
    /**
     * @return Value of the header.
     * 
     */
    public String headerValue() {
        return this.headerValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitorConfigurationReqAuthenticationDetailAuthHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String headerName;
        private String headerValue;
        public Builder() {}
        public Builder(GetMonitorConfigurationReqAuthenticationDetailAuthHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.headerName = defaults.headerName;
    	      this.headerValue = defaults.headerValue;
        }

        @CustomType.Setter
        public Builder headerName(String headerName) {
            if (headerName == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetailAuthHeader", "headerName");
            }
            this.headerName = headerName;
            return this;
        }
        @CustomType.Setter
        public Builder headerValue(String headerValue) {
            if (headerValue == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetailAuthHeader", "headerValue");
            }
            this.headerValue = headerValue;
            return this;
        }
        public GetMonitorConfigurationReqAuthenticationDetailAuthHeader build() {
            final var _resultValue = new GetMonitorConfigurationReqAuthenticationDetailAuthHeader();
            _resultValue.headerName = headerName;
            _resultValue.headerValue = headerValue;
            return _resultValue;
        }
    }
}
