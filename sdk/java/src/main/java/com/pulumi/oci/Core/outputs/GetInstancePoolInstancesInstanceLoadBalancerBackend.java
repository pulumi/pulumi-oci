// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInstancePoolInstancesInstanceLoadBalancerBackend {
    /**
     * @return The health of the backend as observed by the load balancer.
     * 
     */
    private final String backendHealthStatus;
    /**
     * @return The name of the backend in the backend set.
     * 
     */
    private final String backendName;
    /**
     * @return The name of the backend set on the load balancer.
     * 
     */
    private final String backendSetName;
    /**
     * @return The OCID of the load balancer attached to the instance pool.
     * 
     */
    private final String loadBalancerId;
    /**
     * @return The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    private final String state;

    @CustomType.Constructor
    private GetInstancePoolInstancesInstanceLoadBalancerBackend(
        @CustomType.Parameter("backendHealthStatus") String backendHealthStatus,
        @CustomType.Parameter("backendName") String backendName,
        @CustomType.Parameter("backendSetName") String backendSetName,
        @CustomType.Parameter("loadBalancerId") String loadBalancerId,
        @CustomType.Parameter("state") String state) {
        this.backendHealthStatus = backendHealthStatus;
        this.backendName = backendName;
        this.backendSetName = backendSetName;
        this.loadBalancerId = loadBalancerId;
        this.state = state;
    }

    /**
     * @return The health of the backend as observed by the load balancer.
     * 
     */
    public String backendHealthStatus() {
        return this.backendHealthStatus;
    }
    /**
     * @return The name of the backend in the backend set.
     * 
     */
    public String backendName() {
        return this.backendName;
    }
    /**
     * @return The name of the backend set on the load balancer.
     * 
     */
    public String backendSetName() {
        return this.backendSetName;
    }
    /**
     * @return The OCID of the load balancer attached to the instance pool.
     * 
     */
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * @return The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstancePoolInstancesInstanceLoadBalancerBackend defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String backendHealthStatus;
        private String backendName;
        private String backendSetName;
        private String loadBalancerId;
        private String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstancePoolInstancesInstanceLoadBalancerBackend defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendHealthStatus = defaults.backendHealthStatus;
    	      this.backendName = defaults.backendName;
    	      this.backendSetName = defaults.backendSetName;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.state = defaults.state;
        }

        public Builder backendHealthStatus(String backendHealthStatus) {
            this.backendHealthStatus = Objects.requireNonNull(backendHealthStatus);
            return this;
        }
        public Builder backendName(String backendName) {
            this.backendName = Objects.requireNonNull(backendName);
            return this;
        }
        public Builder backendSetName(String backendSetName) {
            this.backendSetName = Objects.requireNonNull(backendSetName);
            return this;
        }
        public Builder loadBalancerId(String loadBalancerId) {
            this.loadBalancerId = Objects.requireNonNull(loadBalancerId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }        public GetInstancePoolInstancesInstanceLoadBalancerBackend build() {
            return new GetInstancePoolInstancesInstanceLoadBalancerBackend(backendHealthStatus, backendName, backendSetName, loadBalancerId, state);
        }
    }
}
