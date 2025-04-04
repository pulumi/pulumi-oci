// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.inputs.GetVirtualNodePoolsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVirtualNodePoolsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualNodePoolsArgs Empty = new GetVirtualNodePoolsArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="clusterId")
    private @Nullable Output<String> clusterId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Optional<Output<String>> clusterId() {
        return Optional.ofNullable(this.clusterId);
    }

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Display name of the virtual node pool. This is a non-unique value.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return Display name of the virtual node pool. This is a non-unique value.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetVirtualNodePoolsFilterArgs>> filters;

    public Optional<Output<List<GetVirtualNodePoolsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
     * 
     */
    @Import(name="states")
    private @Nullable Output<List<String>> states;

    /**
     * @return A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
     * 
     */
    public Optional<Output<List<String>>> states() {
        return Optional.ofNullable(this.states);
    }

    private GetVirtualNodePoolsArgs() {}

    private GetVirtualNodePoolsArgs(GetVirtualNodePoolsArgs $) {
        this.clusterId = $.clusterId;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.states = $.states;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualNodePoolsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualNodePoolsArgs $;

        public Builder() {
            $ = new GetVirtualNodePoolsArgs();
        }

        public Builder(GetVirtualNodePoolsArgs defaults) {
            $ = new GetVirtualNodePoolsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param clusterId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterId(@Nullable Output<String> clusterId) {
            $.clusterId = clusterId;
            return this;
        }

        /**
         * @param clusterId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder clusterId(String clusterId) {
            return clusterId(Output.of(clusterId));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName Display name of the virtual node pool. This is a non-unique value.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName Display name of the virtual node pool. This is a non-unique value.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetVirtualNodePoolsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetVirtualNodePoolsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetVirtualNodePoolsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param states A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
         * 
         * @return builder
         * 
         */
        public Builder states(@Nullable Output<List<String>> states) {
            $.states = states;
            return this;
        }

        /**
         * @param states A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
         * 
         * @return builder
         * 
         */
        public Builder states(List<String> states) {
            return states(Output.of(states));
        }

        /**
         * @param states A virtual node pool lifecycle state to filter on. Can have multiple parameters of this name.
         * 
         * @return builder
         * 
         */
        public Builder states(String... states) {
            return states(List.of(states));
        }

        public GetVirtualNodePoolsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetVirtualNodePoolsArgs", "compartmentId");
            }
            return $;
        }
    }

}
