// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkLoadBalancer.inputs.NetworkLoadBalancersBackendSetsUnifiedBackendArgs;
import com.pulumi.oci.NetworkLoadBalancer.inputs.NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkLoadBalancersBackendSetsUnifiedArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkLoadBalancersBackendSetsUnifiedArgs Empty = new NetworkLoadBalancersBackendSetsUnifiedArgs();

    /**
     * (Updatable) If enabled, NLB supports active-standby backends. The standby backend takes over the traffic when the active node fails, and continues to serve the traffic even when the old active node is back healthy.
     * 
     */
    @Import(name="areOperationallyActiveBackendsPreferred")
    private @Nullable Output<Boolean> areOperationallyActiveBackendsPreferred;

    /**
     * @return (Updatable) If enabled, NLB supports active-standby backends. The standby backend takes over the traffic when the active node fails, and continues to serve the traffic even when the old active node is back healthy.
     * 
     */
    public Optional<Output<Boolean>> areOperationallyActiveBackendsPreferred() {
        return Optional.ofNullable(this.areOperationallyActiveBackendsPreferred);
    }

    /**
     * (Updatable) An array of backends to be associated with the backend set.
     * 
     */
    @Import(name="backends")
    private @Nullable Output<List<NetworkLoadBalancersBackendSetsUnifiedBackendArgs>> backends;

    /**
     * @return (Updatable) An array of backends to be associated with the backend set.
     * 
     */
    public Optional<Output<List<NetworkLoadBalancersBackendSetsUnifiedBackendArgs>>> backends() {
        return Optional.ofNullable(this.backends);
    }

    /**
     * (Updatable) The health check policy configuration. For more information, see [Editing Network Load Balancer Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/HealthCheckPolicies/update-health-check-policy.htm).
     * 
     */
    @Import(name="healthChecker", required=true)
    private Output<NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs> healthChecker;

    /**
     * @return (Updatable) The health check policy configuration. For more information, see [Editing Network Load Balancer Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/HealthCheckPolicies/update-health-check-policy.htm).
     * 
     */
    public Output<NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs> healthChecker() {
        return this.healthChecker;
    }

    /**
     * (Updatable) IP version associated with the backend set.
     * 
     */
    @Import(name="ipVersion")
    private @Nullable Output<String> ipVersion;

    /**
     * @return (Updatable) IP version associated with the backend set.
     * 
     */
    public Optional<Output<String>> ipVersion() {
        return Optional.ofNullable(this.ipVersion);
    }

    /**
     * (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
     * 
     */
    @Import(name="isFailOpen")
    private @Nullable Output<Boolean> isFailOpen;

    /**
     * @return (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
     * 
     */
    public Optional<Output<Boolean>> isFailOpen() {
        return Optional.ofNullable(this.isFailOpen);
    }

    /**
     * (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
     * 
     */
    @Import(name="isInstantFailoverEnabled")
    private @Nullable Output<Boolean> isInstantFailoverEnabled;

    /**
     * @return (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
     * 
     */
    public Optional<Output<Boolean>> isInstantFailoverEnabled() {
        return Optional.ofNullable(this.isInstantFailoverEnabled);
    }

    /**
     * (Updatable) If enabled along with instant failover, the network load balancer will send TCP RST to the clients for the existing connections instead of failing over to a healthy backend. This only applies when using the instant failover. By default, TCP RST is enabled.
     * 
     */
    @Import(name="isInstantFailoverTcpResetEnabled")
    private @Nullable Output<Boolean> isInstantFailoverTcpResetEnabled;

    /**
     * @return (Updatable) If enabled along with instant failover, the network load balancer will send TCP RST to the clients for the existing connections instead of failing over to a healthy backend. This only applies when using the instant failover. By default, TCP RST is enabled.
     * 
     */
    public Optional<Output<Boolean>> isInstantFailoverTcpResetEnabled() {
        return Optional.ofNullable(this.isInstantFailoverTcpResetEnabled);
    }

    /**
     * (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
     * 
     */
    @Import(name="isPreserveSource")
    private @Nullable Output<Boolean> isPreserveSource;

    /**
     * @return (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
     * 
     */
    public Optional<Output<Boolean>> isPreserveSource() {
        return Optional.ofNullable(this.isPreserveSource);
    }

    /**
     * A user-friendly name for the backend set that must be unique and cannot be changed.
     * 
     * Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
     * 
     * Example: `example_backend_set`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A user-friendly name for the backend set that must be unique and cannot be changed.
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
     * (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="policy", required=true)
    private Output<String> policy;

    /**
     * @return (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> policy() {
        return this.policy;
    }

    private NetworkLoadBalancersBackendSetsUnifiedArgs() {}

    private NetworkLoadBalancersBackendSetsUnifiedArgs(NetworkLoadBalancersBackendSetsUnifiedArgs $) {
        this.areOperationallyActiveBackendsPreferred = $.areOperationallyActiveBackendsPreferred;
        this.backends = $.backends;
        this.healthChecker = $.healthChecker;
        this.ipVersion = $.ipVersion;
        this.isFailOpen = $.isFailOpen;
        this.isInstantFailoverEnabled = $.isInstantFailoverEnabled;
        this.isInstantFailoverTcpResetEnabled = $.isInstantFailoverTcpResetEnabled;
        this.isPreserveSource = $.isPreserveSource;
        this.name = $.name;
        this.networkLoadBalancerId = $.networkLoadBalancerId;
        this.policy = $.policy;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkLoadBalancersBackendSetsUnifiedArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkLoadBalancersBackendSetsUnifiedArgs $;

        public Builder() {
            $ = new NetworkLoadBalancersBackendSetsUnifiedArgs();
        }

        public Builder(NetworkLoadBalancersBackendSetsUnifiedArgs defaults) {
            $ = new NetworkLoadBalancersBackendSetsUnifiedArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param areOperationallyActiveBackendsPreferred (Updatable) If enabled, NLB supports active-standby backends. The standby backend takes over the traffic when the active node fails, and continues to serve the traffic even when the old active node is back healthy.
         * 
         * @return builder
         * 
         */
        public Builder areOperationallyActiveBackendsPreferred(@Nullable Output<Boolean> areOperationallyActiveBackendsPreferred) {
            $.areOperationallyActiveBackendsPreferred = areOperationallyActiveBackendsPreferred;
            return this;
        }

        /**
         * @param areOperationallyActiveBackendsPreferred (Updatable) If enabled, NLB supports active-standby backends. The standby backend takes over the traffic when the active node fails, and continues to serve the traffic even when the old active node is back healthy.
         * 
         * @return builder
         * 
         */
        public Builder areOperationallyActiveBackendsPreferred(Boolean areOperationallyActiveBackendsPreferred) {
            return areOperationallyActiveBackendsPreferred(Output.of(areOperationallyActiveBackendsPreferred));
        }

        /**
         * @param backends (Updatable) An array of backends to be associated with the backend set.
         * 
         * @return builder
         * 
         */
        public Builder backends(@Nullable Output<List<NetworkLoadBalancersBackendSetsUnifiedBackendArgs>> backends) {
            $.backends = backends;
            return this;
        }

        /**
         * @param backends (Updatable) An array of backends to be associated with the backend set.
         * 
         * @return builder
         * 
         */
        public Builder backends(List<NetworkLoadBalancersBackendSetsUnifiedBackendArgs> backends) {
            return backends(Output.of(backends));
        }

        /**
         * @param backends (Updatable) An array of backends to be associated with the backend set.
         * 
         * @return builder
         * 
         */
        public Builder backends(NetworkLoadBalancersBackendSetsUnifiedBackendArgs... backends) {
            return backends(List.of(backends));
        }

        /**
         * @param healthChecker (Updatable) The health check policy configuration. For more information, see [Editing Network Load Balancer Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/HealthCheckPolicies/update-health-check-policy.htm).
         * 
         * @return builder
         * 
         */
        public Builder healthChecker(Output<NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs> healthChecker) {
            $.healthChecker = healthChecker;
            return this;
        }

        /**
         * @param healthChecker (Updatable) The health check policy configuration. For more information, see [Editing Network Load Balancer Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/HealthCheckPolicies/update-health-check-policy.htm).
         * 
         * @return builder
         * 
         */
        public Builder healthChecker(NetworkLoadBalancersBackendSetsUnifiedHealthCheckerArgs healthChecker) {
            return healthChecker(Output.of(healthChecker));
        }

        /**
         * @param ipVersion (Updatable) IP version associated with the backend set.
         * 
         * @return builder
         * 
         */
        public Builder ipVersion(@Nullable Output<String> ipVersion) {
            $.ipVersion = ipVersion;
            return this;
        }

        /**
         * @param ipVersion (Updatable) IP version associated with the backend set.
         * 
         * @return builder
         * 
         */
        public Builder ipVersion(String ipVersion) {
            return ipVersion(Output.of(ipVersion));
        }

        /**
         * @param isFailOpen (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
         * 
         * @return builder
         * 
         */
        public Builder isFailOpen(@Nullable Output<Boolean> isFailOpen) {
            $.isFailOpen = isFailOpen;
            return this;
        }

        /**
         * @param isFailOpen (Updatable) If enabled, the network load balancer will continue to distribute traffic in the configured distribution in the event all backends are unhealthy. The value is false by default.
         * 
         * @return builder
         * 
         */
        public Builder isFailOpen(Boolean isFailOpen) {
            return isFailOpen(Output.of(isFailOpen));
        }

        /**
         * @param isInstantFailoverEnabled (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
         * 
         * @return builder
         * 
         */
        public Builder isInstantFailoverEnabled(@Nullable Output<Boolean> isInstantFailoverEnabled) {
            $.isInstantFailoverEnabled = isInstantFailoverEnabled;
            return this;
        }

        /**
         * @param isInstantFailoverEnabled (Updatable) If enabled existing connections will be forwarded to an alternative healthy backend as soon as current backend becomes unhealthy.
         * 
         * @return builder
         * 
         */
        public Builder isInstantFailoverEnabled(Boolean isInstantFailoverEnabled) {
            return isInstantFailoverEnabled(Output.of(isInstantFailoverEnabled));
        }

        /**
         * @param isInstantFailoverTcpResetEnabled (Updatable) If enabled along with instant failover, the network load balancer will send TCP RST to the clients for the existing connections instead of failing over to a healthy backend. This only applies when using the instant failover. By default, TCP RST is enabled.
         * 
         * @return builder
         * 
         */
        public Builder isInstantFailoverTcpResetEnabled(@Nullable Output<Boolean> isInstantFailoverTcpResetEnabled) {
            $.isInstantFailoverTcpResetEnabled = isInstantFailoverTcpResetEnabled;
            return this;
        }

        /**
         * @param isInstantFailoverTcpResetEnabled (Updatable) If enabled along with instant failover, the network load balancer will send TCP RST to the clients for the existing connections instead of failing over to a healthy backend. This only applies when using the instant failover. By default, TCP RST is enabled.
         * 
         * @return builder
         * 
         */
        public Builder isInstantFailoverTcpResetEnabled(Boolean isInstantFailoverTcpResetEnabled) {
            return isInstantFailoverTcpResetEnabled(Output.of(isInstantFailoverTcpResetEnabled));
        }

        /**
         * @param isPreserveSource (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
         * 
         * @return builder
         * 
         */
        public Builder isPreserveSource(@Nullable Output<Boolean> isPreserveSource) {
            $.isPreserveSource = isPreserveSource;
            return this;
        }

        /**
         * @param isPreserveSource (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
         * 
         * @return builder
         * 
         */
        public Builder isPreserveSource(Boolean isPreserveSource) {
            return isPreserveSource(Output.of(isPreserveSource));
        }

        /**
         * @param name A user-friendly name for the backend set that must be unique and cannot be changed.
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
         * @param name A user-friendly name for the backend set that must be unique and cannot be changed.
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
         * @param policy (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder policy(Output<String> policy) {
            $.policy = policy;
            return this;
        }

        /**
         * @param policy (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder policy(String policy) {
            return policy(Output.of(policy));
        }

        public NetworkLoadBalancersBackendSetsUnifiedArgs build() {
            if ($.healthChecker == null) {
                throw new MissingRequiredPropertyException("NetworkLoadBalancersBackendSetsUnifiedArgs", "healthChecker");
            }
            if ($.networkLoadBalancerId == null) {
                throw new MissingRequiredPropertyException("NetworkLoadBalancersBackendSetsUnifiedArgs", "networkLoadBalancerId");
            }
            if ($.policy == null) {
                throw new MissingRequiredPropertyException("NetworkLoadBalancersBackendSetsUnifiedArgs", "policy");
            }
            return $;
        }
    }

}
