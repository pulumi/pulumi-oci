// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.LoadBalancer.BackendSetArgs;
import com.pulumi.oci.LoadBalancer.inputs.BackendSetState;
import com.pulumi.oci.LoadBalancer.outputs.BackendSetBackend;
import com.pulumi.oci.LoadBalancer.outputs.BackendSetHealthChecker;
import com.pulumi.oci.LoadBalancer.outputs.BackendSetLbCookieSessionPersistenceConfiguration;
import com.pulumi.oci.LoadBalancer.outputs.BackendSetSessionPersistenceConfiguration;
import com.pulumi.oci.LoadBalancer.outputs.BackendSetSslConfiguration;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Backend Set resource in Oracle Cloud Infrastructure Load Balancer service.
 * 
 * Adds a backend set to a load balancer.
 * 
 * ## Supported Aliases
 * 
 * * `oci_load_balancer_backendset`
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.LoadBalancer.BackendSet;
 * import com.pulumi.oci.LoadBalancer.BackendSetArgs;
 * import com.pulumi.oci.LoadBalancer.inputs.BackendSetHealthCheckerArgs;
 * import com.pulumi.oci.LoadBalancer.inputs.BackendSetLbCookieSessionPersistenceConfigurationArgs;
 * import com.pulumi.oci.LoadBalancer.inputs.BackendSetSessionPersistenceConfigurationArgs;
 * import com.pulumi.oci.LoadBalancer.inputs.BackendSetSslConfigurationArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testBackendSet = new BackendSet(&#34;testBackendSet&#34;, BackendSetArgs.builder()        
 *             .healthChecker(BackendSetHealthCheckerArgs.builder()
 *                 .protocol(var_.backend_set_health_checker_protocol())
 *                 .intervalMs(var_.backend_set_health_checker_interval_ms())
 *                 .port(var_.backend_set_health_checker_port())
 *                 .responseBodyRegex(var_.backend_set_health_checker_response_body_regex())
 *                 .retries(var_.backend_set_health_checker_retries())
 *                 .returnCode(var_.backend_set_health_checker_return_code())
 *                 .timeoutInMillis(var_.backend_set_health_checker_timeout_in_millis())
 *                 .urlPath(var_.backend_set_health_checker_url_path())
 *                 .build())
 *             .loadBalancerId(oci_load_balancer_load_balancer.test_load_balancer().id())
 *             .policy(var_.backend_set_policy())
 *             .lbCookieSessionPersistenceConfiguration(BackendSetLbCookieSessionPersistenceConfigurationArgs.builder()
 *                 .cookieName(var_.backend_set_lb_cookie_session_persistence_configuration_cookie_name())
 *                 .disableFallback(var_.backend_set_lb_cookie_session_persistence_configuration_disable_fallback())
 *                 .domain(var_.backend_set_lb_cookie_session_persistence_configuration_domain())
 *                 .isHttpOnly(var_.backend_set_lb_cookie_session_persistence_configuration_is_http_only())
 *                 .isSecure(var_.backend_set_lb_cookie_session_persistence_configuration_is_secure())
 *                 .maxAgeInSeconds(var_.backend_set_lb_cookie_session_persistence_configuration_max_age_in_seconds())
 *                 .path(var_.backend_set_lb_cookie_session_persistence_configuration_path())
 *                 .build())
 *             .sessionPersistenceConfiguration(BackendSetSessionPersistenceConfigurationArgs.builder()
 *                 .cookieName(var_.backend_set_session_persistence_configuration_cookie_name())
 *                 .disableFallback(var_.backend_set_session_persistence_configuration_disable_fallback())
 *                 .build())
 *             .sslConfiguration(BackendSetSslConfigurationArgs.builder()
 *                 .certificateIds(var_.backend_set_ssl_configuration_certificate_ids())
 *                 .certificateName(oci_load_balancer_certificate.test_certificate().name())
 *                 .cipherSuiteName(var_.backend_set_ssl_configuration_cipher_suite_name())
 *                 .protocols(var_.backend_set_ssl_configuration_protocols())
 *                 .serverOrderPreference(var_.backend_set_ssl_configuration_server_order_preference())
 *                 .trustedCertificateAuthorityIds(var_.backend_set_ssl_configuration_trusted_certificate_authority_ids())
 *                 .verifyDepth(var_.backend_set_ssl_configuration_verify_depth())
 *                 .verifyPeerCertificate(var_.backend_set_ssl_configuration_verify_peer_certificate())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * ```
 * **Note:** The `sessionPersistenceConfiguration` (application cookie stickiness) and `lbCookieSessionPersistenceConfiguration`
 *       (LB cookie stickiness) attributes are mutually exclusive. To avoid returning an error, configure only one of these two
 *       attributes per backend set.
 * {{% /example %}}
 * 
 * ## Import
 * 
 * BackendSets can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:LoadBalancer/backendSet:BackendSet test_backend_set &#34;loadBalancers/{loadBalancerId}/backendSets/{backendSetName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:LoadBalancer/backendSet:BackendSet")
public class BackendSet extends com.pulumi.resources.CustomResource {
    @Export(name="backends", type=List.class, parameters={BackendSetBackend.class})
    private Output<List<BackendSetBackend>> backends;

    public Output<List<BackendSetBackend>> backends() {
        return this.backends;
    }
    /**
     * (Updatable) The health check policy&#39;s configuration details.
     * 
     */
    @Export(name="healthChecker", type=BackendSetHealthChecker.class, parameters={})
    private Output<BackendSetHealthChecker> healthChecker;

    /**
     * @return (Updatable) The health check policy&#39;s configuration details.
     * 
     */
    public Output<BackendSetHealthChecker> healthChecker() {
        return this.healthChecker;
    }
    /**
     * (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     * 
     */
    @Export(name="lbCookieSessionPersistenceConfiguration", type=BackendSetLbCookieSessionPersistenceConfiguration.class, parameters={})
    private Output<BackendSetLbCookieSessionPersistenceConfiguration> lbCookieSessionPersistenceConfiguration;

    /**
     * @return (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     * 
     */
    public Output<BackendSetLbCookieSessionPersistenceConfiguration> lbCookieSessionPersistenceConfiguration() {
        return this.lbCookieSessionPersistenceConfiguration;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     * 
     */
    @Export(name="loadBalancerId", type=String.class, parameters={})
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * A friendly name for the backend set. It must be unique and it cannot be changed.
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return A friendly name for the backend set. It must be unique and it cannot be changed.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     * 
     */
    @Export(name="policy", type=String.class, parameters={})
    private Output<String> policy;

    /**
     * @return (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     * 
     */
    public Output<String> policy() {
        return this.policy;
    }
    /**
     * (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     * 
     */
    @Export(name="sessionPersistenceConfiguration", type=BackendSetSessionPersistenceConfiguration.class, parameters={})
    private Output<BackendSetSessionPersistenceConfiguration> sessionPersistenceConfiguration;

    /**
     * @return (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     * 
     */
    public Output<BackendSetSessionPersistenceConfiguration> sessionPersistenceConfiguration() {
        return this.sessionPersistenceConfiguration;
    }
    /**
     * (Updatable) The load balancer&#39;s SSL handling configuration details.
     * 
     */
    @Export(name="sslConfiguration", type=BackendSetSslConfiguration.class, parameters={})
    private Output</* @Nullable */ BackendSetSslConfiguration> sslConfiguration;

    /**
     * @return (Updatable) The load balancer&#39;s SSL handling configuration details.
     * 
     */
    public Output<Optional<BackendSetSslConfiguration>> sslConfiguration() {
        return Codegen.optional(this.sslConfiguration);
    }
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    public Output<String> state() {
        return this.state;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public BackendSet(String name) {
        this(name, BackendSetArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public BackendSet(String name, BackendSetArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public BackendSet(String name, BackendSetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LoadBalancer/backendSet:BackendSet", name, args == null ? BackendSetArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private BackendSet(String name, Output<String> id, @Nullable BackendSetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LoadBalancer/backendSet:BackendSet", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static BackendSet get(String name, Output<String> id, @Nullable BackendSetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new BackendSet(name, id, state, options);
    }
}