// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.util.Objects;

@CustomType
public final class GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval {
    /**
     * @return An object value of the parameter.
     * 
     */
    private Double objectValue;

    private GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval() {}
    /**
     * @return An object value of the parameter.
     * 
     */
    public Double objectValue() {
        return this.objectValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double objectValue;
        public Builder() {}
        public Builder(GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectValue = defaults.objectValue;
        }

        @CustomType.Setter
        public Builder objectValue(Double objectValue) {
            if (objectValue == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval", "objectValue");
            }
            this.objectValue = objectValue;
            return this;
        }
        public GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval build() {
            final var _resultValue = new GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValuePollInterval();
            _resultValue.objectValue = objectValue;
            return _resultValue;
        }
    }
}
