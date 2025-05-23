// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam {
    /**
     * @return A string value of the parameter.
     * 
     */
    private String stringValue;

    private GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam() {}
    /**
     * @return A string value of the parameter.
     * 
     */
    public String stringValue() {
        return this.stringValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String stringValue;
        public Builder() {}
        public Builder(GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.stringValue = defaults.stringValue;
        }

        @CustomType.Setter
        public Builder stringValue(String stringValue) {
            if (stringValue == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam", "stringValue");
            }
            this.stringValue = stringValue;
            return this;
        }
        public GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam build() {
            final var _resultValue = new GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParam();
            _resultValue.stringValue = stringValue;
            return _resultValue;
        }
    }
}
