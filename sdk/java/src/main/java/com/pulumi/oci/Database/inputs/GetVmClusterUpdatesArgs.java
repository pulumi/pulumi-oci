// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetVmClusterUpdatesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVmClusterUpdatesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVmClusterUpdatesArgs Empty = new GetVmClusterUpdatesArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetVmClusterUpdatesFilterArgs>> filters;

    public Optional<Output<List<GetVmClusterUpdatesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only resources that match the given update type exactly.
     * 
     */
    @Import(name="updateType")
    private @Nullable Output<String> updateType;

    /**
     * @return A filter to return only resources that match the given update type exactly.
     * 
     */
    public Optional<Output<String>> updateType() {
        return Optional.ofNullable(this.updateType);
    }

    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="vmClusterId", required=true)
    private Output<String> vmClusterId;

    /**
     * @return The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> vmClusterId() {
        return this.vmClusterId;
    }

    private GetVmClusterUpdatesArgs() {}

    private GetVmClusterUpdatesArgs(GetVmClusterUpdatesArgs $) {
        this.filters = $.filters;
        this.state = $.state;
        this.updateType = $.updateType;
        this.vmClusterId = $.vmClusterId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVmClusterUpdatesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVmClusterUpdatesArgs $;

        public Builder() {
            $ = new GetVmClusterUpdatesArgs();
        }

        public Builder(GetVmClusterUpdatesArgs defaults) {
            $ = new GetVmClusterUpdatesArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetVmClusterUpdatesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetVmClusterUpdatesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetVmClusterUpdatesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param updateType A filter to return only resources that match the given update type exactly.
         * 
         * @return builder
         * 
         */
        public Builder updateType(@Nullable Output<String> updateType) {
            $.updateType = updateType;
            return this;
        }

        /**
         * @param updateType A filter to return only resources that match the given update type exactly.
         * 
         * @return builder
         * 
         */
        public Builder updateType(String updateType) {
            return updateType(Output.of(updateType));
        }

        /**
         * @param vmClusterId The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder vmClusterId(Output<String> vmClusterId) {
            $.vmClusterId = vmClusterId;
            return this;
        }

        /**
         * @param vmClusterId The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder vmClusterId(String vmClusterId) {
            return vmClusterId(Output.of(vmClusterId));
        }

        public GetVmClusterUpdatesArgs build() {
            if ($.vmClusterId == null) {
                throw new MissingRequiredPropertyException("GetVmClusterUpdatesArgs", "vmClusterId");
            }
            return $;
        }
    }

}
