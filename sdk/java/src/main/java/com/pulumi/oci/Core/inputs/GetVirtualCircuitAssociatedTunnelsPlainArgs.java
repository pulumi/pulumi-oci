// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetVirtualCircuitAssociatedTunnelsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVirtualCircuitAssociatedTunnelsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualCircuitAssociatedTunnelsPlainArgs Empty = new GetVirtualCircuitAssociatedTunnelsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetVirtualCircuitAssociatedTunnelsFilter> filters;

    public Optional<List<GetVirtualCircuitAssociatedTunnelsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
     * 
     */
    @Import(name="virtualCircuitId", required=true)
    private String virtualCircuitId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
     * 
     */
    public String virtualCircuitId() {
        return this.virtualCircuitId;
    }

    private GetVirtualCircuitAssociatedTunnelsPlainArgs() {}

    private GetVirtualCircuitAssociatedTunnelsPlainArgs(GetVirtualCircuitAssociatedTunnelsPlainArgs $) {
        this.filters = $.filters;
        this.virtualCircuitId = $.virtualCircuitId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualCircuitAssociatedTunnelsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualCircuitAssociatedTunnelsPlainArgs $;

        public Builder() {
            $ = new GetVirtualCircuitAssociatedTunnelsPlainArgs();
        }

        public Builder(GetVirtualCircuitAssociatedTunnelsPlainArgs defaults) {
            $ = new GetVirtualCircuitAssociatedTunnelsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetVirtualCircuitAssociatedTunnelsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetVirtualCircuitAssociatedTunnelsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param virtualCircuitId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
         * 
         * @return builder
         * 
         */
        public Builder virtualCircuitId(String virtualCircuitId) {
            $.virtualCircuitId = virtualCircuitId;
            return this;
        }

        public GetVirtualCircuitAssociatedTunnelsPlainArgs build() {
            $.virtualCircuitId = Objects.requireNonNull($.virtualCircuitId, "expected parameter 'virtualCircuitId' to be non-null");
            return $;
        }
    }

}