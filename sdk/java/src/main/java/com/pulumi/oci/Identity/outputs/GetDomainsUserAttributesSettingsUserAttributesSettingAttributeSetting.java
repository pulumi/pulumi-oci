// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting {
    /**
     * @return End User mutability
     * 
     */
    private String endUserMutability;
    /**
     * @return Specifies the list of User mutabilities allowed.
     * 
     */
    private List<String> endUserMutabilityCanonicalValues;
    /**
     * @return Fully-qualified attribute or complex mapping Name
     * 
     */
    private String name;

    private GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting() {}
    /**
     * @return End User mutability
     * 
     */
    public String endUserMutability() {
        return this.endUserMutability;
    }
    /**
     * @return Specifies the list of User mutabilities allowed.
     * 
     */
    public List<String> endUserMutabilityCanonicalValues() {
        return this.endUserMutabilityCanonicalValues;
    }
    /**
     * @return Fully-qualified attribute or complex mapping Name
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String endUserMutability;
        private List<String> endUserMutabilityCanonicalValues;
        private String name;
        public Builder() {}
        public Builder(GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.endUserMutability = defaults.endUserMutability;
    	      this.endUserMutabilityCanonicalValues = defaults.endUserMutabilityCanonicalValues;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder endUserMutability(String endUserMutability) {
            if (endUserMutability == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting", "endUserMutability");
            }
            this.endUserMutability = endUserMutability;
            return this;
        }
        @CustomType.Setter
        public Builder endUserMutabilityCanonicalValues(List<String> endUserMutabilityCanonicalValues) {
            if (endUserMutabilityCanonicalValues == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting", "endUserMutabilityCanonicalValues");
            }
            this.endUserMutabilityCanonicalValues = endUserMutabilityCanonicalValues;
            return this;
        }
        public Builder endUserMutabilityCanonicalValues(String... endUserMutabilityCanonicalValues) {
            return endUserMutabilityCanonicalValues(List.of(endUserMutabilityCanonicalValues));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting", "name");
            }
            this.name = name;
            return this;
        }
        public GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting build() {
            final var _resultValue = new GetDomainsUserAttributesSettingsUserAttributesSettingAttributeSetting();
            _resultValue.endUserMutability = endUserMutability;
            _resultValue.endUserMutabilityCanonicalValues = endUserMutabilityCanonicalValues;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
