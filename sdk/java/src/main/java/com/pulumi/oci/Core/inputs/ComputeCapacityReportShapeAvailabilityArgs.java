// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeCapacityReportShapeAvailabilityArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeCapacityReportShapeAvailabilityArgs Empty = new ComputeCapacityReportShapeAvailabilityArgs();

    /**
     * A flag denoting whether capacity is available.
     * 
     */
    @Import(name="availabilityStatus")
    private @Nullable Output<String> availabilityStatus;

    /**
     * @return A flag denoting whether capacity is available.
     * 
     */
    public Optional<Output<String>> availabilityStatus() {
        return Optional.ofNullable(this.availabilityStatus);
    }

    /**
     * The total number of new instances that can be created with the specified shape configuration.
     * 
     */
    @Import(name="availableCount")
    private @Nullable Output<String> availableCount;

    /**
     * @return The total number of new instances that can be created with the specified shape configuration.
     * 
     */
    public Optional<Output<String>> availableCount() {
        return Optional.ofNullable(this.availableCount);
    }

    /**
     * The fault domain for the capacity report.
     * 
     * If you do not specify a fault domain, the capacity report includes information about all fault domains.
     * 
     */
    @Import(name="faultDomain")
    private @Nullable Output<String> faultDomain;

    /**
     * @return The fault domain for the capacity report.
     * 
     * If you do not specify a fault domain, the capacity report includes information about all fault domains.
     * 
     */
    public Optional<Output<String>> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }

    /**
     * The shape that you want to request a capacity report for. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
     * 
     */
    @Import(name="instanceShape", required=true)
    private Output<String> instanceShape;

    /**
     * @return The shape that you want to request a capacity report for. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
     * 
     */
    public Output<String> instanceShape() {
        return this.instanceShape;
    }

    /**
     * The shape configuration for a shape in a capacity report.
     * 
     */
    @Import(name="instanceShapeConfig")
    private @Nullable Output<ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs> instanceShapeConfig;

    /**
     * @return The shape configuration for a shape in a capacity report.
     * 
     */
    public Optional<Output<ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs>> instanceShapeConfig() {
        return Optional.ofNullable(this.instanceShapeConfig);
    }

    private ComputeCapacityReportShapeAvailabilityArgs() {}

    private ComputeCapacityReportShapeAvailabilityArgs(ComputeCapacityReportShapeAvailabilityArgs $) {
        this.availabilityStatus = $.availabilityStatus;
        this.availableCount = $.availableCount;
        this.faultDomain = $.faultDomain;
        this.instanceShape = $.instanceShape;
        this.instanceShapeConfig = $.instanceShapeConfig;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeCapacityReportShapeAvailabilityArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeCapacityReportShapeAvailabilityArgs $;

        public Builder() {
            $ = new ComputeCapacityReportShapeAvailabilityArgs();
        }

        public Builder(ComputeCapacityReportShapeAvailabilityArgs defaults) {
            $ = new ComputeCapacityReportShapeAvailabilityArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityStatus A flag denoting whether capacity is available.
         * 
         * @return builder
         * 
         */
        public Builder availabilityStatus(@Nullable Output<String> availabilityStatus) {
            $.availabilityStatus = availabilityStatus;
            return this;
        }

        /**
         * @param availabilityStatus A flag denoting whether capacity is available.
         * 
         * @return builder
         * 
         */
        public Builder availabilityStatus(String availabilityStatus) {
            return availabilityStatus(Output.of(availabilityStatus));
        }

        /**
         * @param availableCount The total number of new instances that can be created with the specified shape configuration.
         * 
         * @return builder
         * 
         */
        public Builder availableCount(@Nullable Output<String> availableCount) {
            $.availableCount = availableCount;
            return this;
        }

        /**
         * @param availableCount The total number of new instances that can be created with the specified shape configuration.
         * 
         * @return builder
         * 
         */
        public Builder availableCount(String availableCount) {
            return availableCount(Output.of(availableCount));
        }

        /**
         * @param faultDomain The fault domain for the capacity report.
         * 
         * If you do not specify a fault domain, the capacity report includes information about all fault domains.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(@Nullable Output<String> faultDomain) {
            $.faultDomain = faultDomain;
            return this;
        }

        /**
         * @param faultDomain The fault domain for the capacity report.
         * 
         * If you do not specify a fault domain, the capacity report includes information about all fault domains.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(String faultDomain) {
            return faultDomain(Output.of(faultDomain));
        }

        /**
         * @param instanceShape The shape that you want to request a capacity report for. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
         * 
         * @return builder
         * 
         */
        public Builder instanceShape(Output<String> instanceShape) {
            $.instanceShape = instanceShape;
            return this;
        }

        /**
         * @param instanceShape The shape that you want to request a capacity report for. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
         * 
         * @return builder
         * 
         */
        public Builder instanceShape(String instanceShape) {
            return instanceShape(Output.of(instanceShape));
        }

        /**
         * @param instanceShapeConfig The shape configuration for a shape in a capacity report.
         * 
         * @return builder
         * 
         */
        public Builder instanceShapeConfig(@Nullable Output<ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs> instanceShapeConfig) {
            $.instanceShapeConfig = instanceShapeConfig;
            return this;
        }

        /**
         * @param instanceShapeConfig The shape configuration for a shape in a capacity report.
         * 
         * @return builder
         * 
         */
        public Builder instanceShapeConfig(ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs instanceShapeConfig) {
            return instanceShapeConfig(Output.of(instanceShapeConfig));
        }

        public ComputeCapacityReportShapeAvailabilityArgs build() {
            $.instanceShape = Objects.requireNonNull($.instanceShape, "expected parameter 'instanceShape' to be non-null");
            return $;
        }
    }

}