// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BackendArgs extends com.pulumi.resources.ResourceArgs {

    public static final BackendArgs Empty = new BackendArgs();

    /**
     * The name of the backend set to add the backend server to.  Example: `example_backend_set`
     * 
     */
    @Import(name="backendsetName", required=true)
    private Output<String> backendsetName;

    /**
     * @return The name of the backend set to add the backend server to.  Example: `example_backend_set`
     * 
     */
    public Output<String> backendsetName() {
        return this.backendsetName;
    }

    /**
     * (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     */
    @Import(name="backup")
    private @Nullable Output<Boolean> backup;

    /**
     * @return (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     */
    public Optional<Output<Boolean>> backup() {
        return Optional.ofNullable(this.backup);
    }

    /**
     * (Updatable) Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
     * 
     */
    @Import(name="drain")
    private @Nullable Output<Boolean> drain;

    /**
     * @return (Updatable) Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> drain() {
        return Optional.ofNullable(this.drain);
    }

    /**
     * The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    @Import(name="ipAddress", required=true)
    private Output<String> ipAddress;

    /**
     * @return The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }

    /**
     * (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    @Import(name="offline")
    private @Nullable Output<Boolean> offline;

    /**
     * @return (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> offline() {
        return Optional.ofNullable(this.offline);
    }

    /**
     * The communication port for the backend server.  Example: `8080`
     * 
     */
    @Import(name="port", required=true)
    private Output<Integer> port;

    /**
     * @return The communication port for the backend server.  Example: `8080`
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }

    /**
     * (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
     * 
     */
    @Import(name="weight")
    private @Nullable Output<Integer> weight;

    /**
     * @return (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
     * 
     */
    public Optional<Output<Integer>> weight() {
        return Optional.ofNullable(this.weight);
    }

    private BackendArgs() {}

    private BackendArgs(BackendArgs $) {
        this.backendsetName = $.backendsetName;
        this.backup = $.backup;
        this.drain = $.drain;
        this.ipAddress = $.ipAddress;
        this.loadBalancerId = $.loadBalancerId;
        this.offline = $.offline;
        this.port = $.port;
        this.weight = $.weight;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BackendArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BackendArgs $;

        public Builder() {
            $ = new BackendArgs();
        }

        public Builder(BackendArgs defaults) {
            $ = new BackendArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backendsetName The name of the backend set to add the backend server to.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendsetName(Output<String> backendsetName) {
            $.backendsetName = backendsetName;
            return this;
        }

        /**
         * @param backendsetName The name of the backend set to add the backend server to.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendsetName(String backendsetName) {
            return backendsetName(Output.of(backendsetName));
        }

        /**
         * @param backup (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
         * 
         * @return builder
         * 
         */
        public Builder backup(@Nullable Output<Boolean> backup) {
            $.backup = backup;
            return this;
        }

        /**
         * @param backup (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
         * 
         * @return builder
         * 
         */
        public Builder backup(Boolean backup) {
            return backup(Output.of(backup));
        }

        /**
         * @param drain (Updatable) Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder drain(@Nullable Output<Boolean> drain) {
            $.drain = drain;
            return this;
        }

        /**
         * @param drain (Updatable) Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder drain(Boolean drain) {
            return drain(Output.of(drain));
        }

        /**
         * @param ipAddress The IP address of the backend server.  Example: `10.0.0.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(Output<String> ipAddress) {
            $.ipAddress = ipAddress;
            return this;
        }

        /**
         * @param ipAddress The IP address of the backend server.  Example: `10.0.0.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(String ipAddress) {
            return ipAddress(Output.of(ipAddress));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        /**
         * @param offline (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder offline(@Nullable Output<Boolean> offline) {
            $.offline = offline;
            return this;
        }

        /**
         * @param offline (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder offline(Boolean offline) {
            return offline(Output.of(offline));
        }

        /**
         * @param port The communication port for the backend server.  Example: `8080`
         * 
         * @return builder
         * 
         */
        public Builder port(Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port The communication port for the backend server.  Example: `8080`
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        /**
         * @param weight (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
         * 
         * @return builder
         * 
         */
        public Builder weight(@Nullable Output<Integer> weight) {
            $.weight = weight;
            return this;
        }

        /**
         * @param weight (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
         * 
         * @return builder
         * 
         */
        public Builder weight(Integer weight) {
            return weight(Output.of(weight));
        }

        public BackendArgs build() {
            $.backendsetName = Objects.requireNonNull($.backendsetName, "expected parameter 'backendsetName' to be non-null");
            $.ipAddress = Objects.requireNonNull($.ipAddress, "expected parameter 'ipAddress' to be non-null");
            $.loadBalancerId = Objects.requireNonNull($.loadBalancerId, "expected parameter 'loadBalancerId' to be non-null");
            $.port = Objects.requireNonNull($.port, "expected parameter 'port' to be non-null");
            return $;
        }
    }

}