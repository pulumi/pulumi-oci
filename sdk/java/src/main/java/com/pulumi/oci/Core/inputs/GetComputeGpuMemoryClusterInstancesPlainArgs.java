// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetComputeGpuMemoryClusterInstancesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetComputeGpuMemoryClusterInstancesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetComputeGpuMemoryClusterInstancesPlainArgs Empty = new GetComputeGpuMemoryClusterInstancesPlainArgs();

    /**
     * The OCID of the compute GPU memory cluster.
     * 
     */
    @Import(name="computeGpuMemoryClusterId", required=true)
    private String computeGpuMemoryClusterId;

    /**
     * @return The OCID of the compute GPU memory cluster.
     * 
     */
    public String computeGpuMemoryClusterId() {
        return this.computeGpuMemoryClusterId;
    }

    @Import(name="filters")
    private @Nullable List<GetComputeGpuMemoryClusterInstancesFilter> filters;

    public Optional<List<GetComputeGpuMemoryClusterInstancesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetComputeGpuMemoryClusterInstancesPlainArgs() {}

    private GetComputeGpuMemoryClusterInstancesPlainArgs(GetComputeGpuMemoryClusterInstancesPlainArgs $) {
        this.computeGpuMemoryClusterId = $.computeGpuMemoryClusterId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetComputeGpuMemoryClusterInstancesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetComputeGpuMemoryClusterInstancesPlainArgs $;

        public Builder() {
            $ = new GetComputeGpuMemoryClusterInstancesPlainArgs();
        }

        public Builder(GetComputeGpuMemoryClusterInstancesPlainArgs defaults) {
            $ = new GetComputeGpuMemoryClusterInstancesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param computeGpuMemoryClusterId The OCID of the compute GPU memory cluster.
         * 
         * @return builder
         * 
         */
        public Builder computeGpuMemoryClusterId(String computeGpuMemoryClusterId) {
            $.computeGpuMemoryClusterId = computeGpuMemoryClusterId;
            return this;
        }

        public Builder filters(@Nullable List<GetComputeGpuMemoryClusterInstancesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetComputeGpuMemoryClusterInstancesFilter... filters) {
            return filters(List.of(filters));
        }

        public GetComputeGpuMemoryClusterInstancesPlainArgs build() {
            if ($.computeGpuMemoryClusterId == null) {
                throw new MissingRequiredPropertyException("GetComputeGpuMemoryClusterInstancesPlainArgs", "computeGpuMemoryClusterId");
            }
            return $;
        }
    }

}
