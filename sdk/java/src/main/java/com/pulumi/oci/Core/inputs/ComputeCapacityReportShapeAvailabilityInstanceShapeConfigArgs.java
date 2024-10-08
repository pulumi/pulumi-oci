// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs Empty = new ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs();

    /**
     * The total amount of memory available to the instance, in gigabytes.
     * 
     */
    @Import(name="memoryInGbs")
    private @Nullable Output<Double> memoryInGbs;

    /**
     * @return The total amount of memory available to the instance, in gigabytes.
     * 
     */
    public Optional<Output<Double>> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }

    /**
     * The number of NVMe drives to be used for storage.
     * 
     */
    @Import(name="nvmes")
    private @Nullable Output<Integer> nvmes;

    /**
     * @return The number of NVMe drives to be used for storage.
     * 
     */
    public Optional<Output<Integer>> nvmes() {
        return Optional.ofNullable(this.nvmes);
    }

    /**
     * The total number of OCPUs available to the instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="ocpus")
    private @Nullable Output<Double> ocpus;

    /**
     * @return The total number of OCPUs available to the instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Double>> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    private ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs() {}

    private ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs(ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs $) {
        this.memoryInGbs = $.memoryInGbs;
        this.nvmes = $.nvmes;
        this.ocpus = $.ocpus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs $;

        public Builder() {
            $ = new ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs();
        }

        public Builder(ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs defaults) {
            $ = new ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param memoryInGbs The total amount of memory available to the instance, in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(@Nullable Output<Double> memoryInGbs) {
            $.memoryInGbs = memoryInGbs;
            return this;
        }

        /**
         * @param memoryInGbs The total amount of memory available to the instance, in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(Double memoryInGbs) {
            return memoryInGbs(Output.of(memoryInGbs));
        }

        /**
         * @param nvmes The number of NVMe drives to be used for storage.
         * 
         * @return builder
         * 
         */
        public Builder nvmes(@Nullable Output<Integer> nvmes) {
            $.nvmes = nvmes;
            return this;
        }

        /**
         * @param nvmes The number of NVMe drives to be used for storage.
         * 
         * @return builder
         * 
         */
        public Builder nvmes(Integer nvmes) {
            return nvmes(Output.of(nvmes));
        }

        /**
         * @param ocpus The total number of OCPUs available to the instance.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder ocpus(@Nullable Output<Double> ocpus) {
            $.ocpus = ocpus;
            return this;
        }

        /**
         * @param ocpus The total number of OCPUs available to the instance.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder ocpus(Double ocpus) {
            return ocpus(Output.of(ocpus));
        }

        public ComputeCapacityReportShapeAvailabilityInstanceShapeConfigArgs build() {
            return $;
        }
    }

}
