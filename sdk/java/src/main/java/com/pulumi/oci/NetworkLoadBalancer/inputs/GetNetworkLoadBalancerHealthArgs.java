// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkLoadBalancerHealthArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkLoadBalancerHealthArgs Empty = new GetNetworkLoadBalancerHealthArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    @Import(name="networkLoadBalancerId", required=true)
    private Output<String> networkLoadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    public Output<String> networkLoadBalancerId() {
        return this.networkLoadBalancerId;
    }

    private GetNetworkLoadBalancerHealthArgs() {}

    private GetNetworkLoadBalancerHealthArgs(GetNetworkLoadBalancerHealthArgs $) {
        this.networkLoadBalancerId = $.networkLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkLoadBalancerHealthArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkLoadBalancerHealthArgs $;

        public Builder() {
            $ = new GetNetworkLoadBalancerHealthArgs();
        }

        public Builder(GetNetworkLoadBalancerHealthArgs defaults) {
            $ = new GetNetworkLoadBalancerHealthArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param networkLoadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
         * 
         * @return builder
         * 
         */
        public Builder networkLoadBalancerId(Output<String> networkLoadBalancerId) {
            $.networkLoadBalancerId = networkLoadBalancerId;
            return this;
        }

        /**
         * @param networkLoadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
         * 
         * @return builder
         * 
         */
        public Builder networkLoadBalancerId(String networkLoadBalancerId) {
            return networkLoadBalancerId(Output.of(networkLoadBalancerId));
        }

        public GetNetworkLoadBalancerHealthArgs build() {
            $.networkLoadBalancerId = Objects.requireNonNull($.networkLoadBalancerId, "expected parameter 'networkLoadBalancerId' to be non-null");
            return $;
        }
    }

}