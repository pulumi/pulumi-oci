// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ListenerArgs extends com.pulumi.resources.ResourceArgs {

    public static final ListenerArgs Empty = new ListenerArgs();

    /**
     * (Updatable) The name of the associated backend set.  Example: `example_backend_set`
     * 
     */
    @Import(name="defaultBackendSetName", required=true)
    private Output<String> defaultBackendSetName;

    /**
     * @return (Updatable) The name of the associated backend set.  Example: `example_backend_set`
     * 
     */
    public Output<String> defaultBackendSetName() {
        return this.defaultBackendSetName;
    }

    /**
     * (Updatable) IP version associated with the listener.
     * 
     */
    @Import(name="ipVersion")
    private @Nullable Output<String> ipVersion;

    /**
     * @return (Updatable) IP version associated with the listener.
     * 
     */
    public Optional<Output<String>> ipVersion() {
        return Optional.ofNullable(this.ipVersion);
    }

    /**
     * A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
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

    /**
     * (Updatable) The communication port for the listener.  Example: `80`
     * 
     */
    @Import(name="port", required=true)
    private Output<Integer> port;

    /**
     * @return (Updatable) The communication port for the listener.  Example: `80`
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }

    /**
     * (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
     * 
     */
    @Import(name="protocol", required=true)
    private Output<String> protocol;

    /**
     * @return (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
     * 
     */
    public Output<String> protocol() {
        return this.protocol;
    }

    private ListenerArgs() {}

    private ListenerArgs(ListenerArgs $) {
        this.defaultBackendSetName = $.defaultBackendSetName;
        this.ipVersion = $.ipVersion;
        this.name = $.name;
        this.networkLoadBalancerId = $.networkLoadBalancerId;
        this.port = $.port;
        this.protocol = $.protocol;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ListenerArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ListenerArgs $;

        public Builder() {
            $ = new ListenerArgs();
        }

        public Builder(ListenerArgs defaults) {
            $ = new ListenerArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param defaultBackendSetName (Updatable) The name of the associated backend set.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder defaultBackendSetName(Output<String> defaultBackendSetName) {
            $.defaultBackendSetName = defaultBackendSetName;
            return this;
        }

        /**
         * @param defaultBackendSetName (Updatable) The name of the associated backend set.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder defaultBackendSetName(String defaultBackendSetName) {
            return defaultBackendSetName(Output.of(defaultBackendSetName));
        }

        /**
         * @param ipVersion (Updatable) IP version associated with the listener.
         * 
         * @return builder
         * 
         */
        public Builder ipVersion(@Nullable Output<String> ipVersion) {
            $.ipVersion = ipVersion;
            return this;
        }

        /**
         * @param ipVersion (Updatable) IP version associated with the listener.
         * 
         * @return builder
         * 
         */
        public Builder ipVersion(String ipVersion) {
            return ipVersion(Output.of(ipVersion));
        }

        /**
         * @param name A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
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

        /**
         * @param port (Updatable) The communication port for the listener.  Example: `80`
         * 
         * @return builder
         * 
         */
        public Builder port(Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port (Updatable) The communication port for the listener.  Example: `80`
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        /**
         * @param protocol (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
         * 
         * @return builder
         * 
         */
        public Builder protocol(Output<String> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
         * 
         * @return builder
         * 
         */
        public Builder protocol(String protocol) {
            return protocol(Output.of(protocol));
        }

        public ListenerArgs build() {
            $.defaultBackendSetName = Objects.requireNonNull($.defaultBackendSetName, "expected parameter 'defaultBackendSetName' to be non-null");
            $.networkLoadBalancerId = Objects.requireNonNull($.networkLoadBalancerId, "expected parameter 'networkLoadBalancerId' to be non-null");
            $.port = Objects.requireNonNull($.port, "expected parameter 'port' to be non-null");
            $.protocol = Objects.requireNonNull($.protocol, "expected parameter 'protocol' to be non-null");
            return $;
        }
    }

}