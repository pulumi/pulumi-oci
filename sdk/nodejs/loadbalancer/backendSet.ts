// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Backend Set resource in Oracle Cloud Infrastructure Load Balancer service.
 *
 * Adds a backend set to a load balancer.
 *
 * ## Supported Aliases
 *
 * * `ociLoadBalancerBackendset`
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSet = new oci.loadbalancer.BackendSet("testBackendSet", {
 *     healthChecker: {
 *         protocol: _var.backend_set_health_checker_protocol,
 *         intervalMs: _var.backend_set_health_checker_interval_ms,
 *         port: _var.backend_set_health_checker_port,
 *         responseBodyRegex: _var.backend_set_health_checker_response_body_regex,
 *         retries: _var.backend_set_health_checker_retries,
 *         returnCode: _var.backend_set_health_checker_return_code,
 *         timeoutInMillis: _var.backend_set_health_checker_timeout_in_millis,
 *         urlPath: _var.backend_set_health_checker_url_path,
 *     },
 *     loadBalancerId: oci_load_balancer_load_balancer.test_load_balancer.id,
 *     policy: _var.backend_set_policy,
 *     lbCookieSessionPersistenceConfiguration: {
 *         cookieName: _var.backend_set_lb_cookie_session_persistence_configuration_cookie_name,
 *         disableFallback: _var.backend_set_lb_cookie_session_persistence_configuration_disable_fallback,
 *         domain: _var.backend_set_lb_cookie_session_persistence_configuration_domain,
 *         isHttpOnly: _var.backend_set_lb_cookie_session_persistence_configuration_is_http_only,
 *         isSecure: _var.backend_set_lb_cookie_session_persistence_configuration_is_secure,
 *         maxAgeInSeconds: _var.backend_set_lb_cookie_session_persistence_configuration_max_age_in_seconds,
 *         path: _var.backend_set_lb_cookie_session_persistence_configuration_path,
 *     },
 *     sessionPersistenceConfiguration: {
 *         cookieName: _var.backend_set_session_persistence_configuration_cookie_name,
 *         disableFallback: _var.backend_set_session_persistence_configuration_disable_fallback,
 *     },
 *     sslConfiguration: {
 *         certificateIds: _var.backend_set_ssl_configuration_certificate_ids,
 *         certificateName: oci_load_balancer_certificate.test_certificate.name,
 *         cipherSuiteName: _var.backend_set_ssl_configuration_cipher_suite_name,
 *         protocols: _var.backend_set_ssl_configuration_protocols,
 *         serverOrderPreference: _var.backend_set_ssl_configuration_server_order_preference,
 *         trustedCertificateAuthorityIds: _var.backend_set_ssl_configuration_trusted_certificate_authority_ids,
 *         verifyDepth: _var.backend_set_ssl_configuration_verify_depth,
 *         verifyPeerCertificate: _var.backend_set_ssl_configuration_verify_peer_certificate,
 *     },
 * });
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
 *  $ pulumi import oci:LoadBalancer/backendSet:BackendSet test_backend_set "loadBalancers/{loadBalancerId}/backendSets/{backendSetName}"
 * ```
 */
export class BackendSet extends pulumi.CustomResource {
    /**
     * Get an existing BackendSet resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: BackendSetState, opts?: pulumi.CustomResourceOptions): BackendSet {
        return new BackendSet(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:LoadBalancer/backendSet:BackendSet';

    /**
     * Returns true if the given object is an instance of BackendSet.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is BackendSet {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === BackendSet.__pulumiType;
    }

    public /*out*/ readonly backends!: pulumi.Output<outputs.LoadBalancer.BackendSetBackend[]>;
    /**
     * (Updatable) The health check policy's configuration details.
     */
    public readonly healthChecker!: pulumi.Output<outputs.LoadBalancer.BackendSetHealthChecker>;
    /**
     * (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     */
    public readonly lbCookieSessionPersistenceConfiguration!: pulumi.Output<outputs.LoadBalancer.BackendSetLbCookieSessionPersistenceConfiguration>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     */
    public readonly loadBalancerId!: pulumi.Output<string>;
    /**
     * A friendly name for the backend set. It must be unique and it cannot be changed.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     */
    public readonly policy!: pulumi.Output<string>;
    /**
     * (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     */
    public readonly sessionPersistenceConfiguration!: pulumi.Output<outputs.LoadBalancer.BackendSetSessionPersistenceConfiguration>;
    /**
     * (Updatable) The load balancer's SSL handling configuration details.
     */
    public readonly sslConfiguration!: pulumi.Output<outputs.LoadBalancer.BackendSetSslConfiguration | undefined>;
    public /*out*/ readonly state!: pulumi.Output<string>;

    /**
     * Create a BackendSet resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: BackendSetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: BackendSetArgs | BackendSetState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as BackendSetState | undefined;
            resourceInputs["backends"] = state ? state.backends : undefined;
            resourceInputs["healthChecker"] = state ? state.healthChecker : undefined;
            resourceInputs["lbCookieSessionPersistenceConfiguration"] = state ? state.lbCookieSessionPersistenceConfiguration : undefined;
            resourceInputs["loadBalancerId"] = state ? state.loadBalancerId : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["policy"] = state ? state.policy : undefined;
            resourceInputs["sessionPersistenceConfiguration"] = state ? state.sessionPersistenceConfiguration : undefined;
            resourceInputs["sslConfiguration"] = state ? state.sslConfiguration : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
        } else {
            const args = argsOrState as BackendSetArgs | undefined;
            if ((!args || args.healthChecker === undefined) && !opts.urn) {
                throw new Error("Missing required property 'healthChecker'");
            }
            if ((!args || args.loadBalancerId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'loadBalancerId'");
            }
            if ((!args || args.policy === undefined) && !opts.urn) {
                throw new Error("Missing required property 'policy'");
            }
            resourceInputs["healthChecker"] = args ? args.healthChecker : undefined;
            resourceInputs["lbCookieSessionPersistenceConfiguration"] = args ? args.lbCookieSessionPersistenceConfiguration : undefined;
            resourceInputs["loadBalancerId"] = args ? args.loadBalancerId : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["policy"] = args ? args.policy : undefined;
            resourceInputs["sessionPersistenceConfiguration"] = args ? args.sessionPersistenceConfiguration : undefined;
            resourceInputs["sslConfiguration"] = args ? args.sslConfiguration : undefined;
            resourceInputs["backends"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(BackendSet.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering BackendSet resources.
 */
export interface BackendSetState {
    backends?: pulumi.Input<pulumi.Input<inputs.LoadBalancer.BackendSetBackend>[]>;
    /**
     * (Updatable) The health check policy's configuration details.
     */
    healthChecker?: pulumi.Input<inputs.LoadBalancer.BackendSetHealthChecker>;
    /**
     * (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     */
    lbCookieSessionPersistenceConfiguration?: pulumi.Input<inputs.LoadBalancer.BackendSetLbCookieSessionPersistenceConfiguration>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     */
    loadBalancerId?: pulumi.Input<string>;
    /**
     * A friendly name for the backend set. It must be unique and it cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     */
    policy?: pulumi.Input<string>;
    /**
     * (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     */
    sessionPersistenceConfiguration?: pulumi.Input<inputs.LoadBalancer.BackendSetSessionPersistenceConfiguration>;
    /**
     * (Updatable) The load balancer's SSL handling configuration details.
     */
    sslConfiguration?: pulumi.Input<inputs.LoadBalancer.BackendSetSslConfiguration>;
    state?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a BackendSet resource.
 */
export interface BackendSetArgs {
    /**
     * (Updatable) The health check policy's configuration details.
     */
    healthChecker: pulumi.Input<inputs.LoadBalancer.BackendSetHealthChecker>;
    /**
     * (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
     */
    lbCookieSessionPersistenceConfiguration?: pulumi.Input<inputs.LoadBalancer.BackendSetLbCookieSessionPersistenceConfiguration>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
     */
    loadBalancerId: pulumi.Input<string>;
    /**
     * A friendly name for the backend set. It must be unique and it cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
     */
    policy: pulumi.Input<string>;
    /**
     * (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
     */
    sessionPersistenceConfiguration?: pulumi.Input<inputs.LoadBalancer.BackendSetSessionPersistenceConfiguration>;
    /**
     * (Updatable) The load balancer's SSL handling configuration details.
     */
    sslConfiguration?: pulumi.Input<inputs.LoadBalancer.BackendSetSslConfiguration>;
}
