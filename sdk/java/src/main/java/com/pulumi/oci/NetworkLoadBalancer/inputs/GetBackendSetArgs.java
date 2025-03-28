// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBackendSetArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBackendSetArgs Empty = new GetBackendSetArgs();

    /**
     * The name of the backend set to retrieve.  Example: `example_backend_set`
     * 
     */
    @Import(name="backendSetName", required=true)
    private Output<String> backendSetName;

    /**
     * @return The name of the backend set to retrieve.  Example: `example_backend_set`
     * 
     */
    public Output<String> backendSetName() {
        return this.backendSetName;
    }

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

    private GetBackendSetArgs() {}

    private GetBackendSetArgs(GetBackendSetArgs $) {
        this.backendSetName = $.backendSetName;
        this.networkLoadBalancerId = $.networkLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBackendSetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBackendSetArgs $;

        public Builder() {
            $ = new GetBackendSetArgs();
        }

        public Builder(GetBackendSetArgs defaults) {
            $ = new GetBackendSetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backendSetName The name of the backend set to retrieve.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(Output<String> backendSetName) {
            $.backendSetName = backendSetName;
            return this;
        }

        /**
         * @param backendSetName The name of the backend set to retrieve.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(String backendSetName) {
            return backendSetName(Output.of(backendSetName));
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

        public GetBackendSetArgs build() {
            if ($.backendSetName == null) {
                throw new MissingRequiredPropertyException("GetBackendSetArgs", "backendSetName");
            }
            if ($.networkLoadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetBackendSetArgs", "networkLoadBalancerId");
            }
            return $;
        }
    }

}
