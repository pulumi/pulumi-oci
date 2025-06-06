// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsCapacityReportShapeAvailabilityShapeConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final BdsCapacityReportShapeAvailabilityShapeConfigArgs Empty = new BdsCapacityReportShapeAvailabilityShapeConfigArgs();

    /**
     * The total amount of memory available to the node, in gigabytes.
     * 
     */
    @Import(name="memoryInGbs")
    private @Nullable Output<Integer> memoryInGbs;

    /**
     * @return The total amount of memory available to the node, in gigabytes.
     * 
     */
    public Optional<Output<Integer>> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }

    /**
     * The number of NVMe drives to be used for storage. A single drive has 6.8 TB available. This parameter is used only for dense shapes.
     * 
     */
    @Import(name="nvmes")
    private @Nullable Output<Integer> nvmes;

    /**
     * @return The number of NVMe drives to be used for storage. A single drive has 6.8 TB available. This parameter is used only for dense shapes.
     * 
     */
    public Optional<Output<Integer>> nvmes() {
        return Optional.ofNullable(this.nvmes);
    }

    /**
     * The total number of OCPUs available to the node.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="ocpus")
    private @Nullable Output<Integer> ocpus;

    /**
     * @return The total number of OCPUs available to the node.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Integer>> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    private BdsCapacityReportShapeAvailabilityShapeConfigArgs() {}

    private BdsCapacityReportShapeAvailabilityShapeConfigArgs(BdsCapacityReportShapeAvailabilityShapeConfigArgs $) {
        this.memoryInGbs = $.memoryInGbs;
        this.nvmes = $.nvmes;
        this.ocpus = $.ocpus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsCapacityReportShapeAvailabilityShapeConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsCapacityReportShapeAvailabilityShapeConfigArgs $;

        public Builder() {
            $ = new BdsCapacityReportShapeAvailabilityShapeConfigArgs();
        }

        public Builder(BdsCapacityReportShapeAvailabilityShapeConfigArgs defaults) {
            $ = new BdsCapacityReportShapeAvailabilityShapeConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param memoryInGbs The total amount of memory available to the node, in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(@Nullable Output<Integer> memoryInGbs) {
            $.memoryInGbs = memoryInGbs;
            return this;
        }

        /**
         * @param memoryInGbs The total amount of memory available to the node, in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(Integer memoryInGbs) {
            return memoryInGbs(Output.of(memoryInGbs));
        }

        /**
         * @param nvmes The number of NVMe drives to be used for storage. A single drive has 6.8 TB available. This parameter is used only for dense shapes.
         * 
         * @return builder
         * 
         */
        public Builder nvmes(@Nullable Output<Integer> nvmes) {
            $.nvmes = nvmes;
            return this;
        }

        /**
         * @param nvmes The number of NVMe drives to be used for storage. A single drive has 6.8 TB available. This parameter is used only for dense shapes.
         * 
         * @return builder
         * 
         */
        public Builder nvmes(Integer nvmes) {
            return nvmes(Output.of(nvmes));
        }

        /**
         * @param ocpus The total number of OCPUs available to the node.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder ocpus(@Nullable Output<Integer> ocpus) {
            $.ocpus = ocpus;
            return this;
        }

        /**
         * @param ocpus The total number of OCPUs available to the node.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder ocpus(Integer ocpus) {
            return ocpus(Output.of(ocpus));
        }

        public BdsCapacityReportShapeAvailabilityShapeConfigArgs build() {
            return $;
        }
    }

}
