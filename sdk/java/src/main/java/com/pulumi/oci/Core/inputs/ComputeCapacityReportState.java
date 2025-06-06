// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.ComputeCapacityReportShapeAvailabilityArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeCapacityReportState extends com.pulumi.resources.ResourceArgs {

    public static final ComputeCapacityReportState Empty = new ComputeCapacityReportState();

    /**
     * The availability domain for the capacity report.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The availability domain for the capacity report.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Information about the shapes in the capacity report.
     * 
     */
    @Import(name="shapeAvailabilities")
    private @Nullable Output<List<ComputeCapacityReportShapeAvailabilityArgs>> shapeAvailabilities;

    /**
     * @return Information about the shapes in the capacity report.
     * 
     */
    public Optional<Output<List<ComputeCapacityReportShapeAvailabilityArgs>>> shapeAvailabilities() {
        return Optional.ofNullable(this.shapeAvailabilities);
    }

    /**
     * The date and time the capacity report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the capacity report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private ComputeCapacityReportState() {}

    private ComputeCapacityReportState(ComputeCapacityReportState $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.shapeAvailabilities = $.shapeAvailabilities;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeCapacityReportState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeCapacityReportState $;

        public Builder() {
            $ = new ComputeCapacityReportState();
        }

        public Builder(ComputeCapacityReportState defaults) {
            $ = new ComputeCapacityReportState(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The availability domain for the capacity report.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain for the capacity report.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param shapeAvailabilities Information about the shapes in the capacity report.
         * 
         * @return builder
         * 
         */
        public Builder shapeAvailabilities(@Nullable Output<List<ComputeCapacityReportShapeAvailabilityArgs>> shapeAvailabilities) {
            $.shapeAvailabilities = shapeAvailabilities;
            return this;
        }

        /**
         * @param shapeAvailabilities Information about the shapes in the capacity report.
         * 
         * @return builder
         * 
         */
        public Builder shapeAvailabilities(List<ComputeCapacityReportShapeAvailabilityArgs> shapeAvailabilities) {
            return shapeAvailabilities(Output.of(shapeAvailabilities));
        }

        /**
         * @param shapeAvailabilities Information about the shapes in the capacity report.
         * 
         * @return builder
         * 
         */
        public Builder shapeAvailabilities(ComputeCapacityReportShapeAvailabilityArgs... shapeAvailabilities) {
            return shapeAvailabilities(List.of(shapeAvailabilities));
        }

        /**
         * @param timeCreated The date and time the capacity report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the capacity report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public ComputeCapacityReportState build() {
            return $;
        }
    }

}
