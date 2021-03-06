// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NodePoolNodeConfigDetailsPlacementConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final NodePoolNodeConfigDetailsPlacementConfigArgs Empty = new NodePoolNodeConfigDetailsPlacementConfigArgs();

    /**
     * (Updatable) The availability domain in which to place nodes. Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return (Updatable) The availability domain in which to place nodes. Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) The OCID of the compute capacity reservation in which to place the compute instance.
     * 
     */
    @Import(name="capacityReservationId")
    private @Nullable Output<String> capacityReservationId;

    /**
     * @return (Updatable) The OCID of the compute capacity reservation in which to place the compute instance.
     * 
     */
    public Optional<Output<String>> capacityReservationId() {
        return Optional.ofNullable(this.capacityReservationId);
    }

    /**
     * (Updatable) The OCID of the subnet in which to place nodes.
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return (Updatable) The OCID of the subnet in which to place nodes.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private NodePoolNodeConfigDetailsPlacementConfigArgs() {}

    private NodePoolNodeConfigDetailsPlacementConfigArgs(NodePoolNodeConfigDetailsPlacementConfigArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.capacityReservationId = $.capacityReservationId;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NodePoolNodeConfigDetailsPlacementConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NodePoolNodeConfigDetailsPlacementConfigArgs $;

        public Builder() {
            $ = new NodePoolNodeConfigDetailsPlacementConfigArgs();
        }

        public Builder(NodePoolNodeConfigDetailsPlacementConfigArgs defaults) {
            $ = new NodePoolNodeConfigDetailsPlacementConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain in which to place nodes. Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain in which to place nodes. Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param capacityReservationId (Updatable) The OCID of the compute capacity reservation in which to place the compute instance.
         * 
         * @return builder
         * 
         */
        public Builder capacityReservationId(@Nullable Output<String> capacityReservationId) {
            $.capacityReservationId = capacityReservationId;
            return this;
        }

        /**
         * @param capacityReservationId (Updatable) The OCID of the compute capacity reservation in which to place the compute instance.
         * 
         * @return builder
         * 
         */
        public Builder capacityReservationId(String capacityReservationId) {
            return capacityReservationId(Output.of(capacityReservationId));
        }

        /**
         * @param subnetId (Updatable) The OCID of the subnet in which to place nodes.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId (Updatable) The OCID of the subnet in which to place nodes.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public NodePoolNodeConfigDetailsPlacementConfigArgs build() {
            $.availabilityDomain = Objects.requireNonNull($.availabilityDomain, "expected parameter 'availabilityDomain' to be non-null");
            $.subnetId = Objects.requireNonNull($.subnetId, "expected parameter 'subnetId' to be non-null");
            return $;
        }
    }

}
