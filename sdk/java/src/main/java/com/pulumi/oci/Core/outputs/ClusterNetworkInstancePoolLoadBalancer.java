// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ClusterNetworkInstancePoolLoadBalancer {
    /**
     * @return The name of the backend set on the load balancer.
     * 
     */
    private @Nullable String backendSetName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
     * 
     */
    private @Nullable String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
     * 
     */
    private @Nullable String instancePoolId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attached to the instance pool.
     * 
     */
    private @Nullable String loadBalancerId;
    /**
     * @return The port value used for the backends.
     * 
     */
    private @Nullable Integer port;
    /**
     * @return The current state of the cluster network.
     * 
     */
    private @Nullable String state;
    /**
     * @return Indicates which VNIC on each instance in the instance pool should be used to associate with the load balancer. Possible values are &#34;PrimaryVnic&#34; or the displayName of one of the secondary VNICs on the instance configuration that is associated with the instance pool.
     * 
     */
    private @Nullable String vnicSelection;

    private ClusterNetworkInstancePoolLoadBalancer() {}
    /**
     * @return The name of the backend set on the load balancer.
     * 
     */
    public Optional<String> backendSetName() {
        return Optional.ofNullable(this.backendSetName);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
     * 
     */
    public Optional<String> instancePoolId() {
        return Optional.ofNullable(this.instancePoolId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attached to the instance pool.
     * 
     */
    public Optional<String> loadBalancerId() {
        return Optional.ofNullable(this.loadBalancerId);
    }
    /**
     * @return The port value used for the backends.
     * 
     */
    public Optional<Integer> port() {
        return Optional.ofNullable(this.port);
    }
    /**
     * @return The current state of the cluster network.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return Indicates which VNIC on each instance in the instance pool should be used to associate with the load balancer. Possible values are &#34;PrimaryVnic&#34; or the displayName of one of the secondary VNICs on the instance configuration that is associated with the instance pool.
     * 
     */
    public Optional<String> vnicSelection() {
        return Optional.ofNullable(this.vnicSelection);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ClusterNetworkInstancePoolLoadBalancer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String backendSetName;
        private @Nullable String id;
        private @Nullable String instancePoolId;
        private @Nullable String loadBalancerId;
        private @Nullable Integer port;
        private @Nullable String state;
        private @Nullable String vnicSelection;
        public Builder() {}
        public Builder(ClusterNetworkInstancePoolLoadBalancer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendSetName = defaults.backendSetName;
    	      this.id = defaults.id;
    	      this.instancePoolId = defaults.instancePoolId;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.port = defaults.port;
    	      this.state = defaults.state;
    	      this.vnicSelection = defaults.vnicSelection;
        }

        @CustomType.Setter
        public Builder backendSetName(@Nullable String backendSetName) {
            this.backendSetName = backendSetName;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instancePoolId(@Nullable String instancePoolId) {
            this.instancePoolId = instancePoolId;
            return this;
        }
        @CustomType.Setter
        public Builder loadBalancerId(@Nullable String loadBalancerId) {
            this.loadBalancerId = loadBalancerId;
            return this;
        }
        @CustomType.Setter
        public Builder port(@Nullable Integer port) {
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vnicSelection(@Nullable String vnicSelection) {
            this.vnicSelection = vnicSelection;
            return this;
        }
        public ClusterNetworkInstancePoolLoadBalancer build() {
            final var o = new ClusterNetworkInstancePoolLoadBalancer();
            o.backendSetName = backendSetName;
            o.id = id;
            o.instancePoolId = instancePoolId;
            o.loadBalancerId = loadBalancerId;
            o.port = port;
            o.state = state;
            o.vnicSelection = vnicSelection;
            return o;
        }
    }
}