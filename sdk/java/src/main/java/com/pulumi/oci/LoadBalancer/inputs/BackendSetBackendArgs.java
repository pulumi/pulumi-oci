// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BackendSetBackendArgs extends com.pulumi.resources.ResourceArgs {

    public static final BackendSetBackendArgs Empty = new BackendSetBackendArgs();

    /**
     * (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     * **Note:** You cannot add a backend server marked as `backup` to a backend set that uses the IP Hash policy.
     * 
     * Example: `false`
     * 
     */
    @Import(name="backup")
    private @Nullable Output<Boolean> backup;

    /**
     * @return (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     * **Note:** You cannot add a backend server marked as `backup` to a backend set that uses the IP Hash policy.
     * 
     * Example: `false`
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
     * (Updatable) The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    @Import(name="ipAddress", required=true)
    private Output<String> ipAddress;

    /**
     * @return (Updatable) The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }

    /**
     * (Updatable) The maximum number of simultaneous connections the load balancer can make to the backend. If this is not set or set to 0 then the maximum number of simultaneous connections the load balancer can make to the backend is unlimited.
     * 
     * If setting maxConnections to some value other than 0 then that value must be greater or equal to 256.
     * 
     * Example: `300`
     * 
     */
    @Import(name="maxConnections")
    private @Nullable Output<Integer> maxConnections;

    /**
     * @return (Updatable) The maximum number of simultaneous connections the load balancer can make to the backend. If this is not set or set to 0 then the maximum number of simultaneous connections the load balancer can make to the backend is unlimited.
     * 
     * If setting maxConnections to some value other than 0 then that value must be greater or equal to 256.
     * 
     * Example: `300`
     * 
     */
    public Optional<Output<Integer>> maxConnections() {
        return Optional.ofNullable(this.maxConnections);
    }

    /**
     * A friendly name for the backend set. It must be unique and it cannot be changed.
     * 
     * Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
     * 
     * Example: `example_backend_set`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A friendly name for the backend set. It must be unique and it cannot be changed.
     * 
     * Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
     * 
     * Example: `example_backend_set`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
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
     * (Updatable) The communication port for the backend server.  Example: `8080`
     * 
     */
    @Import(name="port", required=true)
    private Output<Integer> port;

    /**
     * @return (Updatable) The communication port for the backend server.  Example: `8080`
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

    private BackendSetBackendArgs() {}

    private BackendSetBackendArgs(BackendSetBackendArgs $) {
        this.backup = $.backup;
        this.drain = $.drain;
        this.ipAddress = $.ipAddress;
        this.maxConnections = $.maxConnections;
        this.name = $.name;
        this.offline = $.offline;
        this.port = $.port;
        this.weight = $.weight;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BackendSetBackendArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BackendSetBackendArgs $;

        public Builder() {
            $ = new BackendSetBackendArgs();
        }

        public Builder(BackendSetBackendArgs defaults) {
            $ = new BackendSetBackendArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backup (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
         * 
         * **Note:** You cannot add a backend server marked as `backup` to a backend set that uses the IP Hash policy.
         * 
         * Example: `false`
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
         * **Note:** You cannot add a backend server marked as `backup` to a backend set that uses the IP Hash policy.
         * 
         * Example: `false`
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
         * @param ipAddress (Updatable) The IP address of the backend server.  Example: `10.0.0.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(Output<String> ipAddress) {
            $.ipAddress = ipAddress;
            return this;
        }

        /**
         * @param ipAddress (Updatable) The IP address of the backend server.  Example: `10.0.0.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(String ipAddress) {
            return ipAddress(Output.of(ipAddress));
        }

        /**
         * @param maxConnections (Updatable) The maximum number of simultaneous connections the load balancer can make to the backend. If this is not set or set to 0 then the maximum number of simultaneous connections the load balancer can make to the backend is unlimited.
         * 
         * If setting maxConnections to some value other than 0 then that value must be greater or equal to 256.
         * 
         * Example: `300`
         * 
         * @return builder
         * 
         */
        public Builder maxConnections(@Nullable Output<Integer> maxConnections) {
            $.maxConnections = maxConnections;
            return this;
        }

        /**
         * @param maxConnections (Updatable) The maximum number of simultaneous connections the load balancer can make to the backend. If this is not set or set to 0 then the maximum number of simultaneous connections the load balancer can make to the backend is unlimited.
         * 
         * If setting maxConnections to some value other than 0 then that value must be greater or equal to 256.
         * 
         * Example: `300`
         * 
         * @return builder
         * 
         */
        public Builder maxConnections(Integer maxConnections) {
            return maxConnections(Output.of(maxConnections));
        }

        /**
         * @param name A friendly name for the backend set. It must be unique and it cannot be changed.
         * 
         * Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
         * 
         * Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A friendly name for the backend set. It must be unique and it cannot be changed.
         * 
         * Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
         * 
         * Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
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
         * @param port (Updatable) The communication port for the backend server.  Example: `8080`
         * 
         * @return builder
         * 
         */
        public Builder port(Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port (Updatable) The communication port for the backend server.  Example: `8080`
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

        public BackendSetBackendArgs build() {
            if ($.ipAddress == null) {
                throw new MissingRequiredPropertyException("BackendSetBackendArgs", "ipAddress");
            }
            if ($.port == null) {
                throw new MissingRequiredPropertyException("BackendSetBackendArgs", "port");
            }
            return $;
        }
    }

}
