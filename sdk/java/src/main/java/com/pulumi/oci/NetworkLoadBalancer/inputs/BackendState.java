// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BackendState extends com.pulumi.resources.ResourceArgs {

    public static final BackendState Empty = new BackendState();

    /**
     * The name of the backend set to which to add the backend server.  Example: `example_backend_set`
     * 
     */
    @Import(name="backendSetName")
    private @Nullable Output<String> backendSetName;

    /**
     * @return The name of the backend set to which to add the backend server.  Example: `example_backend_set`
     * 
     */
    public Optional<Output<String>> backendSetName() {
        return Optional.ofNullable(this.backendSetName);
    }

    /**
     * The IP address of the backend server. Example: `10.0.0.3`
     * 
     */
    @Import(name="ipAddress")
    private @Nullable Output<String> ipAddress;

    /**
     * @return The IP address of the backend server. Example: `10.0.0.3`
     * 
     */
    public Optional<Output<String>> ipAddress() {
        return Optional.ofNullable(this.ipAddress);
    }

    /**
     * (Updatable) Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;isBackup&#34; fail the health check policy.  Example: `false`
     * 
     */
    @Import(name="isBackup")
    private @Nullable Output<Boolean> isBackup;

    /**
     * @return (Updatable) Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;isBackup&#34; fail the health check policy.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> isBackup() {
        return Optional.ofNullable(this.isBackup);
    }

    /**
     * (Updatable) Whether the network load balancer should drain this server. Servers marked &#34;isDrain&#34; receive no incoming traffic.  Example: `false`
     * 
     */
    @Import(name="isDrain")
    private @Nullable Output<Boolean> isDrain;

    /**
     * @return (Updatable) Whether the network load balancer should drain this server. Servers marked &#34;isDrain&#34; receive no incoming traffic.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> isDrain() {
        return Optional.ofNullable(this.isDrain);
    }

    /**
     * (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    @Import(name="isOffline")
    private @Nullable Output<Boolean> isOffline;

    /**
     * @return (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> isOffline() {
        return Optional.ofNullable(this.isOffline);
    }

    /**
     * Optional unique name identifying the backend within the backend set. If not specified, then one will be generated. Example: `webServer1`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Optional unique name identifying the backend within the backend set. If not specified, then one will be generated. Example: `webServer1`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    @Import(name="networkLoadBalancerId")
    private @Nullable Output<String> networkLoadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    public Optional<Output<String>> networkLoadBalancerId() {
        return Optional.ofNullable(this.networkLoadBalancerId);
    }

    /**
     * The communication port for the backend server.  Example: `8080`
     * 
     */
    @Import(name="port")
    private @Nullable Output<Integer> port;

    /**
     * @return The communication port for the backend server.  Example: `8080`
     * 
     */
    public Optional<Output<Integer>> port() {
        return Optional.ofNullable(this.port);
    }

    /**
     * The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    /**
     * (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives three times the number of new connections as a server weighted &#39;1&#39;. For more information about network load balancer policies, see [Network Load Balancer Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#Policies).  Example: `3`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="weight")
    private @Nullable Output<Integer> weight;

    /**
     * @return (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives three times the number of new connections as a server weighted &#39;1&#39;. For more information about network load balancer policies, see [Network Load Balancer Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#Policies).  Example: `3`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Integer>> weight() {
        return Optional.ofNullable(this.weight);
    }

    private BackendState() {}

    private BackendState(BackendState $) {
        this.backendSetName = $.backendSetName;
        this.ipAddress = $.ipAddress;
        this.isBackup = $.isBackup;
        this.isDrain = $.isDrain;
        this.isOffline = $.isOffline;
        this.name = $.name;
        this.networkLoadBalancerId = $.networkLoadBalancerId;
        this.port = $.port;
        this.targetId = $.targetId;
        this.weight = $.weight;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BackendState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BackendState $;

        public Builder() {
            $ = new BackendState();
        }

        public Builder(BackendState defaults) {
            $ = new BackendState(Objects.requireNonNull(defaults));
        }

        /**
         * @param backendSetName The name of the backend set to which to add the backend server.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(@Nullable Output<String> backendSetName) {
            $.backendSetName = backendSetName;
            return this;
        }

        /**
         * @param backendSetName The name of the backend set to which to add the backend server.  Example: `example_backend_set`
         * 
         * @return builder
         * 
         */
        public Builder backendSetName(String backendSetName) {
            return backendSetName(Output.of(backendSetName));
        }

        /**
         * @param ipAddress The IP address of the backend server. Example: `10.0.0.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(@Nullable Output<String> ipAddress) {
            $.ipAddress = ipAddress;
            return this;
        }

        /**
         * @param ipAddress The IP address of the backend server. Example: `10.0.0.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(String ipAddress) {
            return ipAddress(Output.of(ipAddress));
        }

        /**
         * @param isBackup (Updatable) Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;isBackup&#34; fail the health check policy.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isBackup(@Nullable Output<Boolean> isBackup) {
            $.isBackup = isBackup;
            return this;
        }

        /**
         * @param isBackup (Updatable) Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;isBackup&#34; fail the health check policy.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isBackup(Boolean isBackup) {
            return isBackup(Output.of(isBackup));
        }

        /**
         * @param isDrain (Updatable) Whether the network load balancer should drain this server. Servers marked &#34;isDrain&#34; receive no incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isDrain(@Nullable Output<Boolean> isDrain) {
            $.isDrain = isDrain;
            return this;
        }

        /**
         * @param isDrain (Updatable) Whether the network load balancer should drain this server. Servers marked &#34;isDrain&#34; receive no incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isDrain(Boolean isDrain) {
            return isDrain(Output.of(isDrain));
        }

        /**
         * @param isOffline (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isOffline(@Nullable Output<Boolean> isOffline) {
            $.isOffline = isOffline;
            return this;
        }

        /**
         * @param isOffline (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isOffline(Boolean isOffline) {
            return isOffline(Output.of(isOffline));
        }

        /**
         * @param name Optional unique name identifying the backend within the backend set. If not specified, then one will be generated. Example: `webServer1`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Optional unique name identifying the backend within the backend set. If not specified, then one will be generated. Example: `webServer1`
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
        public Builder networkLoadBalancerId(@Nullable Output<String> networkLoadBalancerId) {
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
         * @param port The communication port for the backend server.  Example: `8080`
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<Integer> port) {
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
         * @param targetId The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        /**
         * @param weight (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives three times the number of new connections as a server weighted &#39;1&#39;. For more information about network load balancer policies, see [Network Load Balancer Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#Policies).  Example: `3`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder weight(@Nullable Output<Integer> weight) {
            $.weight = weight;
            return this;
        }

        /**
         * @param weight (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives three times the number of new connections as a server weighted &#39;1&#39;. For more information about network load balancer policies, see [Network Load Balancer Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#Policies).  Example: `3`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder weight(Integer weight) {
            return weight(Output.of(weight));
        }

        public BackendState build() {
            return $;
        }
    }

}
