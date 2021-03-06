// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ComputeCapacityReservationInstanceReservationConfig {
    /**
     * @return (Updatable) The fault domain to use for instances created using this capacity configuration. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the capacity is available for an instance that does not specify a fault domain. To change the fault domain for a reservation, delete the reservation and create a new one in the preferred fault domain.
     * 
     */
    private final @Nullable String faultDomain;
    /**
     * @return (Updatable) The shape requested when launching instances using reserved capacity. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance. You can list all available shapes by calling [ListComputeCapacityReservationInstanceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/computeCapacityReservationInstanceShapes/ListComputeCapacityReservationInstanceShapes).
     * 
     */
    private final String instanceShape;
    /**
     * @return (Updatable) The shape configuration requested when launching instances in a compute capacity reservation.
     * 
     */
    private final @Nullable ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig instanceShapeConfig;
    /**
     * @return (Updatable) The total number of instances that can be launched from the capacity configuration.
     * 
     */
    private final String reservedCount;
    /**
     * @return The amount of capacity in use out of the total capacity reserved in this capacity configuration.
     * 
     */
    private final @Nullable String usedCount;

    @CustomType.Constructor
    private ComputeCapacityReservationInstanceReservationConfig(
        @CustomType.Parameter("faultDomain") @Nullable String faultDomain,
        @CustomType.Parameter("instanceShape") String instanceShape,
        @CustomType.Parameter("instanceShapeConfig") @Nullable ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig instanceShapeConfig,
        @CustomType.Parameter("reservedCount") String reservedCount,
        @CustomType.Parameter("usedCount") @Nullable String usedCount) {
        this.faultDomain = faultDomain;
        this.instanceShape = instanceShape;
        this.instanceShapeConfig = instanceShapeConfig;
        this.reservedCount = reservedCount;
        this.usedCount = usedCount;
    }

    /**
     * @return (Updatable) The fault domain to use for instances created using this capacity configuration. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the capacity is available for an instance that does not specify a fault domain. To change the fault domain for a reservation, delete the reservation and create a new one in the preferred fault domain.
     * 
     */
    public Optional<String> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }
    /**
     * @return (Updatable) The shape requested when launching instances using reserved capacity. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance. You can list all available shapes by calling [ListComputeCapacityReservationInstanceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/computeCapacityReservationInstanceShapes/ListComputeCapacityReservationInstanceShapes).
     * 
     */
    public String instanceShape() {
        return this.instanceShape;
    }
    /**
     * @return (Updatable) The shape configuration requested when launching instances in a compute capacity reservation.
     * 
     */
    public Optional<ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig> instanceShapeConfig() {
        return Optional.ofNullable(this.instanceShapeConfig);
    }
    /**
     * @return (Updatable) The total number of instances that can be launched from the capacity configuration.
     * 
     */
    public String reservedCount() {
        return this.reservedCount;
    }
    /**
     * @return The amount of capacity in use out of the total capacity reserved in this capacity configuration.
     * 
     */
    public Optional<String> usedCount() {
        return Optional.ofNullable(this.usedCount);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ComputeCapacityReservationInstanceReservationConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String faultDomain;
        private String instanceShape;
        private @Nullable ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig instanceShapeConfig;
        private String reservedCount;
        private @Nullable String usedCount;

        public Builder() {
    	      // Empty
        }

        public Builder(ComputeCapacityReservationInstanceReservationConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.faultDomain = defaults.faultDomain;
    	      this.instanceShape = defaults.instanceShape;
    	      this.instanceShapeConfig = defaults.instanceShapeConfig;
    	      this.reservedCount = defaults.reservedCount;
    	      this.usedCount = defaults.usedCount;
        }

        public Builder faultDomain(@Nullable String faultDomain) {
            this.faultDomain = faultDomain;
            return this;
        }
        public Builder instanceShape(String instanceShape) {
            this.instanceShape = Objects.requireNonNull(instanceShape);
            return this;
        }
        public Builder instanceShapeConfig(@Nullable ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig instanceShapeConfig) {
            this.instanceShapeConfig = instanceShapeConfig;
            return this;
        }
        public Builder reservedCount(String reservedCount) {
            this.reservedCount = Objects.requireNonNull(reservedCount);
            return this;
        }
        public Builder usedCount(@Nullable String usedCount) {
            this.usedCount = usedCount;
            return this;
        }        public ComputeCapacityReservationInstanceReservationConfig build() {
            return new ComputeCapacityReservationInstanceReservationConfig(faultDomain, instanceShape, instanceShapeConfig, reservedCount, usedCount);
        }
    }
}
