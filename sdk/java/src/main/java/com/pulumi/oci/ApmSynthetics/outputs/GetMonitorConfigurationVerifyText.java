// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitorConfigurationVerifyText {
    /**
     * @return Verification text in the response.
     * 
     */
    private String text;

    private GetMonitorConfigurationVerifyText() {}
    /**
     * @return Verification text in the response.
     * 
     */
    public String text() {
        return this.text;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitorConfigurationVerifyText defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String text;
        public Builder() {}
        public Builder(GetMonitorConfigurationVerifyText defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.text = defaults.text;
        }

        @CustomType.Setter
        public Builder text(String text) {
            if (text == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationVerifyText", "text");
            }
            this.text = text;
            return this;
        }
        public GetMonitorConfigurationVerifyText build() {
            final var _resultValue = new GetMonitorConfigurationVerifyText();
            _resultValue.text = text;
            return _resultValue;
        }
    }
}
