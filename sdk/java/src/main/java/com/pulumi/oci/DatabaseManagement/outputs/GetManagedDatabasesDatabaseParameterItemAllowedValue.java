// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesDatabaseParameterItemAllowedValue {
    /**
     * @return Indicates whether the parameter is set to the default value (`TRUE`) or the parameter value was specified in the parameter file (`FALSE`).
     * 
     */
    private Boolean isDefault;
    /**
     * @return The position (ordinal number) of the parameter value. Useful only for parameters whose values are lists of strings.
     * 
     */
    private Double ordinal;
    /**
     * @return The parameter value.
     * 
     */
    private String value;

    private GetManagedDatabasesDatabaseParameterItemAllowedValue() {}
    /**
     * @return Indicates whether the parameter is set to the default value (`TRUE`) or the parameter value was specified in the parameter file (`FALSE`).
     * 
     */
    public Boolean isDefault() {
        return this.isDefault;
    }
    /**
     * @return The position (ordinal number) of the parameter value. Useful only for parameters whose values are lists of strings.
     * 
     */
    public Double ordinal() {
        return this.ordinal;
    }
    /**
     * @return The parameter value.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesDatabaseParameterItemAllowedValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isDefault;
        private Double ordinal;
        private String value;
        public Builder() {}
        public Builder(GetManagedDatabasesDatabaseParameterItemAllowedValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isDefault = defaults.isDefault;
    	      this.ordinal = defaults.ordinal;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder isDefault(Boolean isDefault) {
            this.isDefault = Objects.requireNonNull(isDefault);
            return this;
        }
        @CustomType.Setter
        public Builder ordinal(Double ordinal) {
            this.ordinal = Objects.requireNonNull(ordinal);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetManagedDatabasesDatabaseParameterItemAllowedValue build() {
            final var o = new GetManagedDatabasesDatabaseParameterItemAllowedValue();
            o.isDefault = isDefault;
            o.ordinal = ordinal;
            o.value = value;
            return o;
        }
    }
}