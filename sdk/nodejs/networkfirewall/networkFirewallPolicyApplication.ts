// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Network Firewall Policy Application resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Creates a new Application inside the Network Firewall Policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkFirewallPolicyApplication = new oci.networkfirewall.NetworkFirewallPolicyApplication("testNetworkFirewallPolicyApplication", {
 *     icmpType: _var.network_firewall_policy_application_icmp_type,
 *     networkFirewallPolicyId: oci_network_firewall_network_firewall_policy.test_network_firewall_policy.id,
 *     type: _var.network_firewall_policy_application_type,
 *     icmpCode: _var.network_firewall_policy_application_icmp_code,
 * });
 * ```
 *
 * ## Import
 *
 * NetworkFirewallPolicyApplications can be imported using the `name`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:NetworkFirewall/networkFirewallPolicyApplication:NetworkFirewallPolicyApplication test_network_firewall_policy_application "networkFirewallPolicies/{networkFirewallPolicyId}/applications/{applicationName}"
 * ```
 */
export class NetworkFirewallPolicyApplication extends pulumi.CustomResource {
    /**
     * Get an existing NetworkFirewallPolicyApplication resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: NetworkFirewallPolicyApplicationState, opts?: pulumi.CustomResourceOptions): NetworkFirewallPolicyApplication {
        return new NetworkFirewallPolicyApplication(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:NetworkFirewall/networkFirewallPolicyApplication:NetworkFirewallPolicyApplication';

    /**
     * Returns true if the given object is an instance of NetworkFirewallPolicyApplication.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is NetworkFirewallPolicyApplication {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === NetworkFirewallPolicyApplication.__pulumiType;
    }

    /**
     * (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     */
    public readonly icmpCode!: pulumi.Output<number>;
    /**
     * (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     */
    public readonly icmpType!: pulumi.Output<number>;
    /**
     * Name of the application
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    public readonly networkFirewallPolicyId!: pulumi.Output<string>;
    /**
     * OCID of the Network Firewall Policy this application belongs to.
     */
    public /*out*/ readonly parentResourceId!: pulumi.Output<string>;
    /**
     * Describes the type of application. The accepted values are - * ICMP * ICMP_V6
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly type!: pulumi.Output<string>;

    /**
     * Create a NetworkFirewallPolicyApplication resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: NetworkFirewallPolicyApplicationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: NetworkFirewallPolicyApplicationArgs | NetworkFirewallPolicyApplicationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as NetworkFirewallPolicyApplicationState | undefined;
            resourceInputs["icmpCode"] = state ? state.icmpCode : undefined;
            resourceInputs["icmpType"] = state ? state.icmpType : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["networkFirewallPolicyId"] = state ? state.networkFirewallPolicyId : undefined;
            resourceInputs["parentResourceId"] = state ? state.parentResourceId : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
        } else {
            const args = argsOrState as NetworkFirewallPolicyApplicationArgs | undefined;
            if ((!args || args.icmpType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'icmpType'");
            }
            if ((!args || args.networkFirewallPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'networkFirewallPolicyId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["icmpCode"] = args ? args.icmpCode : undefined;
            resourceInputs["icmpType"] = args ? args.icmpType : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["networkFirewallPolicyId"] = args ? args.networkFirewallPolicyId : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["parentResourceId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(NetworkFirewallPolicyApplication.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering NetworkFirewallPolicyApplication resources.
 */
export interface NetworkFirewallPolicyApplicationState {
    /**
     * (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     */
    icmpCode?: pulumi.Input<number>;
    /**
     * (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     */
    icmpType?: pulumi.Input<number>;
    /**
     * Name of the application
     */
    name?: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId?: pulumi.Input<string>;
    /**
     * OCID of the Network Firewall Policy this application belongs to.
     */
    parentResourceId?: pulumi.Input<string>;
    /**
     * Describes the type of application. The accepted values are - * ICMP * ICMP_V6
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a NetworkFirewallPolicyApplication resource.
 */
export interface NetworkFirewallPolicyApplicationArgs {
    /**
     * (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     */
    icmpCode?: pulumi.Input<number>;
    /**
     * (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     */
    icmpType: pulumi.Input<number>;
    /**
     * Name of the application
     */
    name?: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
    /**
     * Describes the type of application. The accepted values are - * ICMP * ICMP_V6
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type: pulumi.Input<string>;
}