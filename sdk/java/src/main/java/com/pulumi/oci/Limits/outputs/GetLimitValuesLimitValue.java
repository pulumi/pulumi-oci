// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Limits.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetLimitValuesLimitValue {
    /**
     * @return Filter entries by availability domain. This implies that only AD-specific values are returned.
     * 
     */
    private String availabilityDomain;
    /**
     * @return Optional field, can be used to see a specific resource limit value.
     * 
     */
    private String name;
    /**
     * @return Filter entries by scope type.
     * 
     */
    private String scopeType;
    /**
     * @return The resource limit value.
     * 
     */
    private String value;

    private GetLimitValuesLimitValue() {}
    /**
     * @return Filter entries by availability domain. This implies that only AD-specific values are returned.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return Optional field, can be used to see a specific resource limit value.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Filter entries by scope type.
     * 
     */
    public String scopeType() {
        return this.scopeType;
    }
    /**
     * @return The resource limit value.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLimitValuesLimitValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String name;
        private String scopeType;
        private String value;
        public Builder() {}
        public Builder(GetLimitValuesLimitValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.name = defaults.name;
    	      this.scopeType = defaults.scopeType;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder scopeType(String scopeType) {
            this.scopeType = Objects.requireNonNull(scopeType);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetLimitValuesLimitValue build() {
            final var o = new GetLimitValuesLimitValue();
            o.availabilityDomain = availabilityDomain;
            o.name = name;
            o.scopeType = scopeType;
            o.value = value;
            return o;
        }
    }
}