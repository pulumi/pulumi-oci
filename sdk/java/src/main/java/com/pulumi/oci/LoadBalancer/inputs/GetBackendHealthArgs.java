// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBackendHealthArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBackendHealthArgs Empty = new GetBackendHealthArgs();

    /**
     * The IP address and port of the backend server to retrieve the health status for.  Example: `10.0.0.3:8080`
     * 
     */
    @Import(name="backendName", required=true)
    private Output<String> backendName;

    /**
     * @return The IP address and port of the backend server to retrieve the health status for.  Example: `10.0.0.3:8080`
     * 
     */
    public Output<String> backendName() {
        return this.backendName;
    }

    /**
     * The name of the backend set associated with the backend server to retrieve the health status for.  Example: `example_backend_set`
     * 
     */
    @Import(name="backendSetName", required=true)
    private Output<String> backendSetName;

    /**
     * @return The name of the backend set associated with the backend server to retrieve the health status for.  Example: `example_backend_set`
     * 
     */
    public Output<String> backendSetName() {
        return this.backendSetName;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend server health status to be retrieved.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend server health status to be retrieved.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }

    private GetBackendHealthArgs() {}

    private GetBackendHealthArgs(GetBackendHealthArgs $) {
        this.backendName = $.backendName;
        this.backendSetName = $.backendSetName;
        this.loadBalancerId = $.loadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBackendHealthArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBackendHealthArgs $;

        public Builder() {
            $ = new GetBackendHealthArgs();
        }

        public Builder(GetBackendHealthArgs defaults) {
            $ = new GetBackendHealthArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backendName The IP address and port of the backend server to retrieve the health status for.  Example: `10.0.0.3:8080`
         * 
         * @return builder
         * 
         */
        public Builder backendName(Output<String> backendName) {
            $.backendName = backendName;
            return this;
        }

        /**
         * @param backendName The IP address and port of the backend server to retrieve the health status for.  Example: `10.0.0.3:8080`
         * 
         * @return builder
         * 
         */
        public Builder backendName(String backendName) {
            return backendName(Output.of(backendName));
        }

        /**
         * @param backendSetName The name of the backend set associated with the backend server to retrieve the health status for.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(Output<String> backendSetName) {
            $.backendSetName = backendSetName;
            return this;
        }

        /**
         * @param backendSetName The name of the backend set associated with the backend server to retrieve the health status for.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(String backendSetName) {
            return backendSetName(Output.of(backendSetName));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend server health status to be retrieved.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend server health status to be retrieved.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        public GetBackendHealthArgs build() {
            if ($.backendName == null) {
                throw new MissingRequiredPropertyException("GetBackendHealthArgs", "backendName");
            }
            if ($.backendSetName == null) {
                throw new MissingRequiredPropertyException("GetBackendHealthArgs", "backendSetName");
            }
            if ($.loadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetBackendHealthArgs", "loadBalancerId");
            }
            return $;
        }
    }

}
