// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The name of the available shape used to launch instances in a compute capacity reservation.
     * 
     */
    private String instanceShape;

    private GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape() {}
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The name of the available shape used to launch instances in a compute capacity reservation.
     * 
     */
    public String instanceShape() {
        return this.instanceShape;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String instanceShape;
        public Builder() {}
        public Builder(GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.instanceShape = defaults.instanceShape;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder instanceShape(String instanceShape) {
            if (instanceShape == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape", "instanceShape");
            }
            this.instanceShape = instanceShape;
            return this;
        }
        public GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape build() {
            final var _resultValue = new GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.instanceShape = instanceShape;
            return _resultValue;
        }
    }
}
