// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Backend Set resource in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Adds a backend set to a network load balancer.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSet = new oci.networkloadbalancer.BackendSet("testBackendSet", {
 *     healthChecker: {
 *         protocol: _var.backend_set_health_checker_protocol,
 *         intervalInMillis: _var.backend_set_health_checker_interval_in_millis,
 *         port: _var.backend_set_health_checker_port,
 *         requestData: _var.backend_set_health_checker_request_data,
 *         responseBodyRegex: _var.backend_set_health_checker_response_body_regex,
 *         responseData: _var.backend_set_health_checker_response_data,
 *         retries: _var.backend_set_health_checker_retries,
 *         returnCode: _var.backend_set_health_checker_return_code,
 *         timeoutInMillis: _var.backend_set_health_checker_timeout_in_millis,
 *         urlPath: _var.backend_set_health_checker_url_path,
 *     },
 *     networkLoadBalancerId: oci_network_load_balancer_network_load_balancer.test_network_load_balancer.id,
 *     policy: _var.backend_set_policy,
 *     ipVersion: _var.backend_set_ip_version,
 *     isPreserveSource: _var.backend_set_is_preserve_source,
 * });
 * ```
 *
 * ## Import
 *
 * BackendSets can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:NetworkLoadBalancer/backendSet:BackendSet test_backend_set "networkLoadBalancers/{networkLoadBalancerId}/backendSets/{backendSetName}"
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
    public static readonly __pulumiType = 'oci:NetworkLoadBalancer/backendSet:BackendSet';

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

    /**
     * Array of backends.
     */
    public /*out*/ readonly backends!: pulumi.Output<outputs.NetworkLoadBalancer.BackendSetBackend[]>;
    /**
     * (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
     */
    public readonly healthChecker!: pulumi.Output<outputs.NetworkLoadBalancer.BackendSetHealthChecker>;
    /**
     * (Updatable) IP version associated with the backend set.
     */
    public readonly ipVersion!: pulumi.Output<string>;
    /**
     * (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
     */
    public readonly isPreserveSource!: pulumi.Output<boolean>;
    /**
     * A user-friendly name for the backend set that must be unique and cannot be changed.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    public readonly networkLoadBalancerId!: pulumi.Output<string>;
    /**
     * (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
     */
    public readonly policy!: pulumi.Output<string>;

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
            resourceInputs["ipVersion"] = state ? state.ipVersion : undefined;
            resourceInputs["isPreserveSource"] = state ? state.isPreserveSource : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["networkLoadBalancerId"] = state ? state.networkLoadBalancerId : undefined;
            resourceInputs["policy"] = state ? state.policy : undefined;
        } else {
            const args = argsOrState as BackendSetArgs | undefined;
            if ((!args || args.healthChecker === undefined) && !opts.urn) {
                throw new Error("Missing required property 'healthChecker'");
            }
            if ((!args || args.networkLoadBalancerId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'networkLoadBalancerId'");
            }
            if ((!args || args.policy === undefined) && !opts.urn) {
                throw new Error("Missing required property 'policy'");
            }
            resourceInputs["healthChecker"] = args ? args.healthChecker : undefined;
            resourceInputs["ipVersion"] = args ? args.ipVersion : undefined;
            resourceInputs["isPreserveSource"] = args ? args.isPreserveSource : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["networkLoadBalancerId"] = args ? args.networkLoadBalancerId : undefined;
            resourceInputs["policy"] = args ? args.policy : undefined;
            resourceInputs["backends"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(BackendSet.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering BackendSet resources.
 */
export interface BackendSetState {
    /**
     * Array of backends.
     */
    backends?: pulumi.Input<pulumi.Input<inputs.NetworkLoadBalancer.BackendSetBackend>[]>;
    /**
     * (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
     */
    healthChecker?: pulumi.Input<inputs.NetworkLoadBalancer.BackendSetHealthChecker>;
    /**
     * (Updatable) IP version associated with the backend set.
     */
    ipVersion?: pulumi.Input<string>;
    /**
     * (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
     */
    isPreserveSource?: pulumi.Input<boolean>;
    /**
     * A user-friendly name for the backend set that must be unique and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId?: pulumi.Input<string>;
    /**
     * (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
     */
    policy?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a BackendSet resource.
 */
export interface BackendSetArgs {
    /**
     * (Updatable) The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
     */
    healthChecker: pulumi.Input<inputs.NetworkLoadBalancer.BackendSetHealthChecker>;
    /**
     * (Updatable) IP version associated with the backend set.
     */
    ipVersion?: pulumi.Input<string>;
    /**
     * (Updatable) If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
     */
    isPreserveSource?: pulumi.Input<boolean>;
    /**
     * A user-friendly name for the backend set that must be unique and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: pulumi.Input<string>;
    /**
     * (Updatable) The network load balancer policy for the backend set.  Example: `FIVE_TUPLE``
     */
    policy: pulumi.Input<string>;
}