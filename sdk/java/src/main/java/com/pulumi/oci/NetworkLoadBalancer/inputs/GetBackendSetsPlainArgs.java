// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.NetworkLoadBalancer.inputs.GetBackendSetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBackendSetsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBackendSetsPlainArgs Empty = new GetBackendSetsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetBackendSetsFilter> filters;

    public Optional<List<GetBackendSetsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    @Import(name="networkLoadBalancerId", required=true)
    private String networkLoadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    public String networkLoadBalancerId() {
        return this.networkLoadBalancerId;
    }

    private GetBackendSetsPlainArgs() {}

    private GetBackendSetsPlainArgs(GetBackendSetsPlainArgs $) {
        this.filters = $.filters;
        this.networkLoadBalancerId = $.networkLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBackendSetsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBackendSetsPlainArgs $;

        public Builder() {
            $ = new GetBackendSetsPlainArgs();
        }

        public Builder(GetBackendSetsPlainArgs defaults) {
            $ = new GetBackendSetsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetBackendSetsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetBackendSetsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param networkLoadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
         * 
         * @return builder
         * 
         */
        public Builder networkLoadBalancerId(String networkLoadBalancerId) {
            $.networkLoadBalancerId = networkLoadBalancerId;
            return this;
        }

        public GetBackendSetsPlainArgs build() {
            $.networkLoadBalancerId = Objects.requireNonNull($.networkLoadBalancerId, "expected parameter 'networkLoadBalancerId' to be non-null");
            return $;
        }
    }

}