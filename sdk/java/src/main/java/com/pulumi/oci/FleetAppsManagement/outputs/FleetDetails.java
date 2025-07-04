// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FleetDetails {
    /**
     * @return Type of the Fleet. PRODUCT - A fleet of product-specific resources for a product type. ENVIRONMENT - A fleet of environment-specific resources for a product stack. GROUP - A fleet of a fleet of either environment or product fleets. GENERIC - A fleet of resources selected dynamically or manually for reporting purposes
     * 
     */
    private @Nullable String fleetType;

    private FleetDetails() {}
    /**
     * @return Type of the Fleet. PRODUCT - A fleet of product-specific resources for a product type. ENVIRONMENT - A fleet of environment-specific resources for a product stack. GROUP - A fleet of a fleet of either environment or product fleets. GENERIC - A fleet of resources selected dynamically or manually for reporting purposes
     * 
     */
    public Optional<String> fleetType() {
        return Optional.ofNullable(this.fleetType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FleetDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String fleetType;
        public Builder() {}
        public Builder(FleetDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fleetType = defaults.fleetType;
        }

        @CustomType.Setter
        public Builder fleetType(@Nullable String fleetType) {

            this.fleetType = fleetType;
            return this;
        }
        public FleetDetails build() {
            final var _resultValue = new FleetDetails();
            _resultValue.fleetType = fleetType;
            return _resultValue;
        }
    }
}
