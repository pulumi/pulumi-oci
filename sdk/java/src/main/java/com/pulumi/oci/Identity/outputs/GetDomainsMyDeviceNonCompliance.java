// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyDeviceNonCompliance {
    /**
     * @return Device Compliance Action
     * 
     */
    private String action;
    /**
     * @return Device Compliance name
     * 
     */
    private String name;
    /**
     * @return The identifier of the user
     * 
     */
    private String value;

    private GetDomainsMyDeviceNonCompliance() {}
    /**
     * @return Device Compliance Action
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return Device Compliance name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The identifier of the user
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyDeviceNonCompliance defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private String name;
        private String value;
        public Builder() {}
        public Builder(GetDomainsMyDeviceNonCompliance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder action(String action) {
            if (action == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyDeviceNonCompliance", "action");
            }
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyDeviceNonCompliance", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyDeviceNonCompliance", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsMyDeviceNonCompliance build() {
            final var _resultValue = new GetDomainsMyDeviceNonCompliance();
            _resultValue.action = action;
            _resultValue.name = name;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
