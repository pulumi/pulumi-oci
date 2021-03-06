// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LoadBalancer.inputs.BackendSetBackendArgs;
import com.pulumi.oci.LoadBalancer.inputs.BackendSetHealthCheckerArgs;
import com.pulumi.oci.LoadBalancer.inputs.BackendSetLbCookieSessionPersistenceConfigurationArgs;
import com.pulumi.oci.LoadBalancer.inputs.BackendSetSessionPersistenceConfigurationArgs;
import com.pulumi.oci.LoadBalancer.inputs.BackendSetSslConfigurationArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BackendSetState extends com.pulumi.resources.ResourceArgs {

    public static final BackendSetState Empty = new BackendSetState();

    @Import(name="backends")
    private @Nullable Output<List<BackendSetBackendArgs>> backends;

    public Optional<Output<List<BackendSetBackendArgs>>> backends() {
        return Optional.ofNullable(this.backends);
    }

    /**
     * (Updatable) The health check policy&#39;s configuration details.
     * 
     */
    @Import(name="healthChecker")
    private @Nullable Output<BackendSetHealthCheckerArgs> healthChecker;

    /**
     * @return (Updatable) The health check policy&#39;s configuration details.
     * 
     */
    public Optional<Output<BackendSetHealthCheckerArgs>> healthChecker() {
        return Optional.ofNullable(this.healthChecker);
    }

    /**
     * (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     * 
     */
    @Import(name="lbCookieSessionPersistenceConfiguration")
    private @Nullable Output<BackendSetLbCookieSessionPersistenceConfigurationArgs> lbCookieSessionPersistenceConfiguration;

    /**
     * @return (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     * 
     */
    public Optional<Output<BackendSetLbCookieSessionPersistenceConfigurationArgs>> lbCookieSessionPersistenceConfiguration() {
        return Optional.ofNullable(this.lbCookieSessionPersistenceConfiguration);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     * 
     */
    @Import(name="loadBalancerId")
    private @Nullable Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     * 
     */
    public Optional<Output<String>> loadBalancerId() {
        return Optional.ofNullable(this.loadBalancerId);
    }

    /**
     * A friendly name for the backend set. It must be unique and it cannot be changed.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A friendly name for the backend set. It must be unique and it cannot be changed.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     * 
     */
    @Import(name="policy")
    private @Nullable Output<String> policy;

    /**
     * @return (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     * 
     */
    public Optional<Output<String>> policy() {
        return Optional.ofNullable(this.policy);
    }

    /**
     * (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     * 
     */
    @Import(name="sessionPersistenceConfiguration")
    private @Nullable Output<BackendSetSessionPersistenceConfigurationArgs> sessionPersistenceConfiguration;

    /**
     * @return (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     * 
     */
    public Optional<Output<BackendSetSessionPersistenceConfigurationArgs>> sessionPersistenceConfiguration() {
        return Optional.ofNullable(this.sessionPersistenceConfiguration);
    }

    /**
     * (Updatable) The load balancer&#39;s SSL handling configuration details.
     * 
     */
    @Import(name="sslConfiguration")
    private @Nullable Output<BackendSetSslConfigurationArgs> sslConfiguration;

    /**
     * @return (Updatable) The load balancer&#39;s SSL handling configuration details.
     * 
     */
    public Optional<Output<BackendSetSslConfigurationArgs>> sslConfiguration() {
        return Optional.ofNullable(this.sslConfiguration);
    }

    @Import(name="state")
    private @Nullable Output<String> state;

    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private BackendSetState() {}

    private BackendSetState(BackendSetState $) {
        this.backends = $.backends;
        this.healthChecker = $.healthChecker;
        this.lbCookieSessionPersistenceConfiguration = $.lbCookieSessionPersistenceConfiguration;
        this.loadBalancerId = $.loadBalancerId;
        this.name = $.name;
        this.policy = $.policy;
        this.sessionPersistenceConfiguration = $.sessionPersistenceConfiguration;
        this.sslConfiguration = $.sslConfiguration;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BackendSetState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BackendSetState $;

        public Builder() {
            $ = new BackendSetState();
        }

        public Builder(BackendSetState defaults) {
            $ = new BackendSetState(Objects.requireNonNull(defaults));
        }

        public Builder backends(@Nullable Output<List<BackendSetBackendArgs>> backends) {
            $.backends = backends;
            return this;
        }

        public Builder backends(List<BackendSetBackendArgs> backends) {
            return backends(Output.of(backends));
        }

        public Builder backends(BackendSetBackendArgs... backends) {
            return backends(List.of(backends));
        }

        /**
         * @param healthChecker (Updatable) The health check policy&#39;s configuration details.
         * 
         * @return builder
         * 
         */
        public Builder healthChecker(@Nullable Output<BackendSetHealthCheckerArgs> healthChecker) {
            $.healthChecker = healthChecker;
            return this;
        }

        /**
         * @param healthChecker (Updatable) The health check policy&#39;s configuration details.
         * 
         * @return builder
         * 
         */
        public Builder healthChecker(BackendSetHealthCheckerArgs healthChecker) {
            return healthChecker(Output.of(healthChecker));
        }

        /**
         * @param lbCookieSessionPersistenceConfiguration (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
         * 
         * @return builder
         * 
         */
        public Builder lbCookieSessionPersistenceConfiguration(@Nullable Output<BackendSetLbCookieSessionPersistenceConfigurationArgs> lbCookieSessionPersistenceConfiguration) {
            $.lbCookieSessionPersistenceConfiguration = lbCookieSessionPersistenceConfiguration;
            return this;
        }

        /**
         * @param lbCookieSessionPersistenceConfiguration (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
         * 
         * @return builder
         * 
         */
        public Builder lbCookieSessionPersistenceConfiguration(BackendSetLbCookieSessionPersistenceConfigurationArgs lbCookieSessionPersistenceConfiguration) {
            return lbCookieSessionPersistenceConfiguration(Output.of(lbCookieSessionPersistenceConfiguration));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(@Nullable Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        /**
         * @param name A friendly name for the backend set. It must be unique and it cannot be changed.
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
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param policy (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
         * 
         * @return builder
         * 
         */
        public Builder policy(@Nullable Output<String> policy) {
            $.policy = policy;
            return this;
        }

        /**
         * @param policy (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
         * 
         * @return builder
         * 
         */
        public Builder policy(String policy) {
            return policy(Output.of(policy));
        }

        /**
         * @param sessionPersistenceConfiguration (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
         * 
         * @return builder
         * 
         */
        public Builder sessionPersistenceConfiguration(@Nullable Output<BackendSetSessionPersistenceConfigurationArgs> sessionPersistenceConfiguration) {
            $.sessionPersistenceConfiguration = sessionPersistenceConfiguration;
            return this;
        }

        /**
         * @param sessionPersistenceConfiguration (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
         * 
         * @return builder
         * 
         */
        public Builder sessionPersistenceConfiguration(BackendSetSessionPersistenceConfigurationArgs sessionPersistenceConfiguration) {
            return sessionPersistenceConfiguration(Output.of(sessionPersistenceConfiguration));
        }

        /**
         * @param sslConfiguration (Updatable) The load balancer&#39;s SSL handling configuration details.
         * 
         * @return builder
         * 
         */
        public Builder sslConfiguration(@Nullable Output<BackendSetSslConfigurationArgs> sslConfiguration) {
            $.sslConfiguration = sslConfiguration;
            return this;
        }

        /**
         * @param sslConfiguration (Updatable) The load balancer&#39;s SSL handling configuration details.
         * 
         * @return builder
         * 
         */
        public Builder sslConfiguration(BackendSetSslConfigurationArgs sslConfiguration) {
            return sslConfiguration(Output.of(sslConfiguration));
        }

        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        public Builder state(String state) {
            return state(Output.of(state));
        }

        public BackendSetState build() {
            return $;
        }
    }

}
