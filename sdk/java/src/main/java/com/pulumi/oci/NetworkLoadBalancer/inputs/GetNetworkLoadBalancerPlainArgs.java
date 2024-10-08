// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkLoadBalancerPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkLoadBalancerPlainArgs Empty = new GetNetworkLoadBalancerPlainArgs();

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

    private GetNetworkLoadBalancerPlainArgs() {}

    private GetNetworkLoadBalancerPlainArgs(GetNetworkLoadBalancerPlainArgs $) {
        this.networkLoadBalancerId = $.networkLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkLoadBalancerPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkLoadBalancerPlainArgs $;

        public Builder() {
            $ = new GetNetworkLoadBalancerPlainArgs();
        }

        public Builder(GetNetworkLoadBalancerPlainArgs defaults) {
            $ = new GetNetworkLoadBalancerPlainArgs(Objects.requireNonNull(defaults));
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

        public GetNetworkLoadBalancerPlainArgs build() {
            if ($.networkLoadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetNetworkLoadBalancerPlainArgs", "networkLoadBalancerId");
            }
            return $;
        }
    }

}
