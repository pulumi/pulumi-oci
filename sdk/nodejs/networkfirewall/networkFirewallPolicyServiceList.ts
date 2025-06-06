// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Network Firewall Policy Service List resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Creates a new ServiceList for the Network Firewall Policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkFirewallPolicyServiceList = new oci.networkfirewall.NetworkFirewallPolicyServiceList("test_network_firewall_policy_service_list", {
 *     name: networkFirewallPolicyServiceListName,
 *     networkFirewallPolicyId: testNetworkFirewallPolicy.id,
 *     services: networkFirewallPolicyServiceListServices,
 * });
 * ```
 *
 * ## Import
 *
 * NetworkFirewallPolicyServiceLists can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:NetworkFirewall/networkFirewallPolicyServiceList:NetworkFirewallPolicyServiceList test_network_firewall_policy_service_list "networkFirewallPolicies/{networkFirewallPolicyId}/serviceLists/{serviceListName}"
 * ```
 */
export class NetworkFirewallPolicyServiceList extends pulumi.CustomResource {
    /**
     * Get an existing NetworkFirewallPolicyServiceList resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: NetworkFirewallPolicyServiceListState, opts?: pulumi.CustomResourceOptions): NetworkFirewallPolicyServiceList {
        return new NetworkFirewallPolicyServiceList(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:NetworkFirewall/networkFirewallPolicyServiceList:NetworkFirewallPolicyServiceList';

    /**
     * Returns true if the given object is an instance of NetworkFirewallPolicyServiceList.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is NetworkFirewallPolicyServiceList {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === NetworkFirewallPolicyServiceList.__pulumiType;
    }

    /**
     * Name of the service Group.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    public readonly networkFirewallPolicyId!: pulumi.Output<string>;
    /**
     * OCID of the Network Firewall Policy this serviceList belongs to.
     */
    public /*out*/ readonly parentResourceId!: pulumi.Output<string>;
    /**
     * (Updatable) Collection of service names. The services referenced in the service list must already be present in the policy before being used in the service list. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly services!: pulumi.Output<string[]>;
    /**
     * Count of total services in the given service List.
     */
    public /*out*/ readonly totalServices!: pulumi.Output<number>;

    /**
     * Create a NetworkFirewallPolicyServiceList resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: NetworkFirewallPolicyServiceListArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: NetworkFirewallPolicyServiceListArgs | NetworkFirewallPolicyServiceListState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as NetworkFirewallPolicyServiceListState | undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["networkFirewallPolicyId"] = state ? state.networkFirewallPolicyId : undefined;
            resourceInputs["parentResourceId"] = state ? state.parentResourceId : undefined;
            resourceInputs["services"] = state ? state.services : undefined;
            resourceInputs["totalServices"] = state ? state.totalServices : undefined;
        } else {
            const args = argsOrState as NetworkFirewallPolicyServiceListArgs | undefined;
            if ((!args || args.networkFirewallPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'networkFirewallPolicyId'");
            }
            if ((!args || args.services === undefined) && !opts.urn) {
                throw new Error("Missing required property 'services'");
            }
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["networkFirewallPolicyId"] = args ? args.networkFirewallPolicyId : undefined;
            resourceInputs["services"] = args ? args.services : undefined;
            resourceInputs["parentResourceId"] = undefined /*out*/;
            resourceInputs["totalServices"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(NetworkFirewallPolicyServiceList.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering NetworkFirewallPolicyServiceList resources.
 */
export interface NetworkFirewallPolicyServiceListState {
    /**
     * Name of the service Group.
     */
    name?: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId?: pulumi.Input<string>;
    /**
     * OCID of the Network Firewall Policy this serviceList belongs to.
     */
    parentResourceId?: pulumi.Input<string>;
    /**
     * (Updatable) Collection of service names. The services referenced in the service list must already be present in the policy before being used in the service list. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    services?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Count of total services in the given service List.
     */
    totalServices?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a NetworkFirewallPolicyServiceList resource.
 */
export interface NetworkFirewallPolicyServiceListArgs {
    /**
     * Name of the service Group.
     */
    name?: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
    /**
     * (Updatable) Collection of service names. The services referenced in the service list must already be present in the policy before being used in the service list. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    services: pulumi.Input<pulumi.Input<string>[]>;
}
