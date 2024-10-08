// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkLoadBalancerHealthPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkLoadBalancerHealthPlainArgs Empty = new GetNetworkLoadBalancerHealthPlainArgs();

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

    private GetNetworkLoadBalancerHealthPlainArgs() {}

    private GetNetworkLoadBalancerHealthPlainArgs(GetNetworkLoadBalancerHealthPlainArgs $) {
        this.networkLoadBalancerId = $.networkLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkLoadBalancerHealthPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkLoadBalancerHealthPlainArgs $;

        public Builder() {
            $ = new GetNetworkLoadBalancerHealthPlainArgs();
        }

        public Builder(GetNetworkLoadBalancerHealthPlainArgs defaults) {
            $ = new GetNetworkLoadBalancerHealthPlainArgs(Objects.requireNonNull(defaults));
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

        public GetNetworkLoadBalancerHealthPlainArgs build() {
            if ($.networkLoadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetNetworkLoadBalancerHealthPlainArgs", "networkLoadBalancerId");
            }
            return $;
        }
    }

}
