// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetShapesShapePlatformConfigOptionMemoryEncryptionOption {
    /**
     * @return Whether virtualization instructions can be enabled.
     * 
     */
    private List<Boolean> allowedValues;
    /**
     * @return Whether virtualization instructions are enabled by default.
     * 
     */
    private Boolean isDefaultEnabled;

    private GetShapesShapePlatformConfigOptionMemoryEncryptionOption() {}
    /**
     * @return Whether virtualization instructions can be enabled.
     * 
     */
    public List<Boolean> allowedValues() {
        return this.allowedValues;
    }
    /**
     * @return Whether virtualization instructions are enabled by default.
     * 
     */
    public Boolean isDefaultEnabled() {
        return this.isDefaultEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapesShapePlatformConfigOptionMemoryEncryptionOption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<Boolean> allowedValues;
        private Boolean isDefaultEnabled;
        public Builder() {}
        public Builder(GetShapesShapePlatformConfigOptionMemoryEncryptionOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedValues = defaults.allowedValues;
    	      this.isDefaultEnabled = defaults.isDefaultEnabled;
        }

        @CustomType.Setter
        public Builder allowedValues(List<Boolean> allowedValues) {
            if (allowedValues == null) {
              throw new MissingRequiredPropertyException("GetShapesShapePlatformConfigOptionMemoryEncryptionOption", "allowedValues");
            }
            this.allowedValues = allowedValues;
            return this;
        }
        public Builder allowedValues(Boolean... allowedValues) {
            return allowedValues(List.of(allowedValues));
        }
        @CustomType.Setter
        public Builder isDefaultEnabled(Boolean isDefaultEnabled) {
            if (isDefaultEnabled == null) {
              throw new MissingRequiredPropertyException("GetShapesShapePlatformConfigOptionMemoryEncryptionOption", "isDefaultEnabled");
            }
            this.isDefaultEnabled = isDefaultEnabled;
            return this;
        }
        public GetShapesShapePlatformConfigOptionMemoryEncryptionOption build() {
            final var _resultValue = new GetShapesShapePlatformConfigOptionMemoryEncryptionOption();
            _resultValue.allowedValues = allowedValues;
            _resultValue.isDefaultEnabled = isDefaultEnabled;
            return _resultValue;
        }
    }
}
