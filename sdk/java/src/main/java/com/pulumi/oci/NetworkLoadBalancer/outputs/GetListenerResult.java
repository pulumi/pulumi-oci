// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetListenerResult {
    /**
     * @return The name of the associated backend set.  Example: `example_backend_set`
     * 
     */
    private String defaultBackendSetName;
    private String id;
    /**
     * @return IP version associated with the listener.
     * 
     */
    private String ipVersion;
    private String listenerName;
    /**
     * @return A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
     * 
     */
    private String name;
    private String networkLoadBalancerId;
    /**
     * @return The communication port for the listener.  Example: `80`
     * 
     */
    private Integer port;
    /**
     * @return The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
     * 
     */
    private String protocol;

    private GetListenerResult() {}
    /**
     * @return The name of the associated backend set.  Example: `example_backend_set`
     * 
     */
    public String defaultBackendSetName() {
        return this.defaultBackendSetName;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return IP version associated with the listener.
     * 
     */
    public String ipVersion() {
        return this.ipVersion;
    }
    public String listenerName() {
        return this.listenerName;
    }
    /**
     * @return A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
     * 
     */
    public String name() {
        return this.name;
    }
    public String networkLoadBalancerId() {
        return this.networkLoadBalancerId;
    }
    /**
     * @return The communication port for the listener.  Example: `80`
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
     * 
     */
    public String protocol() {
        return this.protocol;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListenerResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String defaultBackendSetName;
        private String id;
        private String ipVersion;
        private String listenerName;
        private String name;
        private String networkLoadBalancerId;
        private Integer port;
        private String protocol;
        public Builder() {}
        public Builder(GetListenerResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultBackendSetName = defaults.defaultBackendSetName;
    	      this.id = defaults.id;
    	      this.ipVersion = defaults.ipVersion;
    	      this.listenerName = defaults.listenerName;
    	      this.name = defaults.name;
    	      this.networkLoadBalancerId = defaults.networkLoadBalancerId;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
        }

        @CustomType.Setter
        public Builder defaultBackendSetName(String defaultBackendSetName) {
            this.defaultBackendSetName = Objects.requireNonNull(defaultBackendSetName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder ipVersion(String ipVersion) {
            this.ipVersion = Objects.requireNonNull(ipVersion);
            return this;
        }
        @CustomType.Setter
        public Builder listenerName(String listenerName) {
            this.listenerName = Objects.requireNonNull(listenerName);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder networkLoadBalancerId(String networkLoadBalancerId) {
            this.networkLoadBalancerId = Objects.requireNonNull(networkLoadBalancerId);
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        public GetListenerResult build() {
            final var o = new GetListenerResult();
            o.defaultBackendSetName = defaultBackendSetName;
            o.id = id;
            o.ipVersion = ipVersion;
            o.listenerName = listenerName;
            o.name = name;
            o.networkLoadBalancerId = networkLoadBalancerId;
            o.port = port;
            o.protocol = protocol;
            return o;
        }
    }
}