// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetComputeGpuMemoryFabricsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetComputeGpuMemoryFabricsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetComputeGpuMemoryFabricsPlainArgs Empty = new GetComputeGpuMemoryFabricsPlainArgs();

    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return ComputeGpuMemoryFabricSummary resources that match the given fabric health.
     * 
     */
    @Import(name="computeGpuMemoryFabricHealth")
    private @Nullable String computeGpuMemoryFabricHealth;

    /**
     * @return A filter to return ComputeGpuMemoryFabricSummary resources that match the given fabric health.
     * 
     */
    public Optional<String> computeGpuMemoryFabricHealth() {
        return Optional.ofNullable(this.computeGpuMemoryFabricHealth);
    }

    /**
     * A filter to return only the listings that matches the given GPU memory fabric id.
     * 
     */
    @Import(name="computeGpuMemoryFabricId")
    private @Nullable String computeGpuMemoryFabricId;

    /**
     * @return A filter to return only the listings that matches the given GPU memory fabric id.
     * 
     */
    public Optional<String> computeGpuMemoryFabricId() {
        return Optional.ofNullable(this.computeGpuMemoryFabricId);
    }

    /**
     * A filter to return ComputeGpuMemoryFabricSummary resources that match the given lifecycle state.
     * 
     */
    @Import(name="computeGpuMemoryFabricLifecycleState")
    private @Nullable String computeGpuMemoryFabricLifecycleState;

    /**
     * @return A filter to return ComputeGpuMemoryFabricSummary resources that match the given lifecycle state.
     * 
     */
    public Optional<String> computeGpuMemoryFabricLifecycleState() {
        return Optional.ofNullable(this.computeGpuMemoryFabricLifecycleState);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
     * 
     */
    @Import(name="computeHpcIslandId")
    private @Nullable String computeHpcIslandId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
     * 
     */
    public Optional<String> computeHpcIslandId() {
        return Optional.ofNullable(this.computeHpcIslandId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
     * 
     */
    @Import(name="computeNetworkBlockId")
    private @Nullable String computeNetworkBlockId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
     * 
     */
    public Optional<String> computeNetworkBlockId() {
        return Optional.ofNullable(this.computeNetworkBlockId);
    }

    /**
     * A filter to return only resources that match the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetComputeGpuMemoryFabricsFilter> filters;

    public Optional<List<GetComputeGpuMemoryFabricsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetComputeGpuMemoryFabricsPlainArgs() {}

    private GetComputeGpuMemoryFabricsPlainArgs(GetComputeGpuMemoryFabricsPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.computeGpuMemoryFabricHealth = $.computeGpuMemoryFabricHealth;
        this.computeGpuMemoryFabricId = $.computeGpuMemoryFabricId;
        this.computeGpuMemoryFabricLifecycleState = $.computeGpuMemoryFabricLifecycleState;
        this.computeHpcIslandId = $.computeHpcIslandId;
        this.computeNetworkBlockId = $.computeNetworkBlockId;
        this.displayName = $.displayName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetComputeGpuMemoryFabricsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetComputeGpuMemoryFabricsPlainArgs $;

        public Builder() {
            $ = new GetComputeGpuMemoryFabricsPlainArgs();
        }

        public Builder(GetComputeGpuMemoryFabricsPlainArgs defaults) {
            $ = new GetComputeGpuMemoryFabricsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param computeGpuMemoryFabricHealth A filter to return ComputeGpuMemoryFabricSummary resources that match the given fabric health.
         * 
         * @return builder
         * 
         */
        public Builder computeGpuMemoryFabricHealth(@Nullable String computeGpuMemoryFabricHealth) {
            $.computeGpuMemoryFabricHealth = computeGpuMemoryFabricHealth;
            return this;
        }

        /**
         * @param computeGpuMemoryFabricId A filter to return only the listings that matches the given GPU memory fabric id.
         * 
         * @return builder
         * 
         */
        public Builder computeGpuMemoryFabricId(@Nullable String computeGpuMemoryFabricId) {
            $.computeGpuMemoryFabricId = computeGpuMemoryFabricId;
            return this;
        }

        /**
         * @param computeGpuMemoryFabricLifecycleState A filter to return ComputeGpuMemoryFabricSummary resources that match the given lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder computeGpuMemoryFabricLifecycleState(@Nullable String computeGpuMemoryFabricLifecycleState) {
            $.computeGpuMemoryFabricLifecycleState = computeGpuMemoryFabricLifecycleState;
            return this;
        }

        /**
         * @param computeHpcIslandId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
         * 
         * @return builder
         * 
         */
        public Builder computeHpcIslandId(@Nullable String computeHpcIslandId) {
            $.computeHpcIslandId = computeHpcIslandId;
            return this;
        }

        /**
         * @param computeNetworkBlockId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
         * 
         * @return builder
         * 
         */
        public Builder computeNetworkBlockId(@Nullable String computeNetworkBlockId) {
            $.computeNetworkBlockId = computeNetworkBlockId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetComputeGpuMemoryFabricsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetComputeGpuMemoryFabricsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetComputeGpuMemoryFabricsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetComputeGpuMemoryFabricsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
