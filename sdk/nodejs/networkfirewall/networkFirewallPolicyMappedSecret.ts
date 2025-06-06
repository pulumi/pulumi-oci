// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Network Firewall Policy Mapped Secret resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Creates a new Mapped Secret for the Network Firewall Policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkFirewallPolicyMappedSecret = new oci.networkfirewall.NetworkFirewallPolicyMappedSecret("test_network_firewall_policy_mapped_secret", {
 *     name: networkFirewallPolicyMappedSecretName,
 *     networkFirewallPolicyId: testNetworkFirewallPolicy.id,
 *     source: networkFirewallPolicyMappedSecretSource,
 *     type: networkFirewallPolicyMappedSecretType,
 *     vaultSecretId: testSecret.id,
 *     versionNumber: networkFirewallPolicyMappedSecretVersionNumber,
 * });
 * ```
 *
 * ## Import
 *
 * NetworkFirewallPolicyMappedSecrets can be imported using the `name`, e.g.
 *
 * ```sh
 * $ pulumi import oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret test_network_firewall_policy_mapped_secret "networkFirewallPolicies/{networkFirewallPolicyId}/mappedSecrets/{mappedSecretName}"
 * ```
 */
export class NetworkFirewallPolicyMappedSecret extends pulumi.CustomResource {
    /**
     * Get an existing NetworkFirewallPolicyMappedSecret resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: NetworkFirewallPolicyMappedSecretState, opts?: pulumi.CustomResourceOptions): NetworkFirewallPolicyMappedSecret {
        return new NetworkFirewallPolicyMappedSecret(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret';

    /**
     * Returns true if the given object is an instance of NetworkFirewallPolicyMappedSecret.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is NetworkFirewallPolicyMappedSecret {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === NetworkFirewallPolicyMappedSecret.__pulumiType;
    }

    /**
     * Unique name to identify the group of urls to be used in the policy rules.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    public readonly networkFirewallPolicyId!: pulumi.Output<string>;
    /**
     * OCID of the Network Firewall Policy this Mapped Secret belongs to.
     */
    public /*out*/ readonly parentResourceId!: pulumi.Output<string>;
    /**
     * Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
     */
    public readonly source!: pulumi.Output<string>;
    /**
     * Type of the secrets mapped based on the policy.
     * * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
     * * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * (Updatable) OCID for the Vault Secret to be used.
     */
    public readonly vaultSecretId!: pulumi.Output<string>;
    /**
     * (Updatable) Version number of the secret to be used.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly versionNumber!: pulumi.Output<number>;

    /**
     * Create a NetworkFirewallPolicyMappedSecret resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: NetworkFirewallPolicyMappedSecretArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: NetworkFirewallPolicyMappedSecretArgs | NetworkFirewallPolicyMappedSecretState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as NetworkFirewallPolicyMappedSecretState | undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["networkFirewallPolicyId"] = state ? state.networkFirewallPolicyId : undefined;
            resourceInputs["parentResourceId"] = state ? state.parentResourceId : undefined;
            resourceInputs["source"] = state ? state.source : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["vaultSecretId"] = state ? state.vaultSecretId : undefined;
            resourceInputs["versionNumber"] = state ? state.versionNumber : undefined;
        } else {
            const args = argsOrState as NetworkFirewallPolicyMappedSecretArgs | undefined;
            if ((!args || args.networkFirewallPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'networkFirewallPolicyId'");
            }
            if ((!args || args.source === undefined) && !opts.urn) {
                throw new Error("Missing required property 'source'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            if ((!args || args.vaultSecretId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vaultSecretId'");
            }
            if ((!args || args.versionNumber === undefined) && !opts.urn) {
                throw new Error("Missing required property 'versionNumber'");
            }
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["networkFirewallPolicyId"] = args ? args.networkFirewallPolicyId : undefined;
            resourceInputs["source"] = args ? args.source : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["vaultSecretId"] = args ? args.vaultSecretId : undefined;
            resourceInputs["versionNumber"] = args ? args.versionNumber : undefined;
            resourceInputs["parentResourceId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(NetworkFirewallPolicyMappedSecret.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering NetworkFirewallPolicyMappedSecret resources.
 */
export interface NetworkFirewallPolicyMappedSecretState {
    /**
     * Unique name to identify the group of urls to be used in the policy rules.
     */
    name?: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId?: pulumi.Input<string>;
    /**
     * OCID of the Network Firewall Policy this Mapped Secret belongs to.
     */
    parentResourceId?: pulumi.Input<string>;
    /**
     * Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
     */
    source?: pulumi.Input<string>;
    /**
     * Type of the secrets mapped based on the policy.
     * * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
     * * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
     */
    type?: pulumi.Input<string>;
    /**
     * (Updatable) OCID for the Vault Secret to be used.
     */
    vaultSecretId?: pulumi.Input<string>;
    /**
     * (Updatable) Version number of the secret to be used.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    versionNumber?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a NetworkFirewallPolicyMappedSecret resource.
 */
export interface NetworkFirewallPolicyMappedSecretArgs {
    /**
     * Unique name to identify the group of urls to be used in the policy rules.
     */
    name?: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
    /**
     * Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
     */
    source: pulumi.Input<string>;
    /**
     * Type of the secrets mapped based on the policy.
     * * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
     * * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
     */
    type: pulumi.Input<string>;
    /**
     * (Updatable) OCID for the Vault Secret to be used.
     */
    vaultSecretId: pulumi.Input<string>;
    /**
     * (Updatable) Version number of the secret to be used.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    versionNumber: pulumi.Input<number>;
}
