// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Network Firewall Policy Decryption Rule resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get Decryption Rule by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyDecryptionRule(args: GetNetworkFirewallPolicyDecryptionRuleArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkFirewallPolicyDecryptionRuleResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkFirewall/getNetworkFirewallPolicyDecryptionRule:getNetworkFirewallPolicyDecryptionRule", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyDecryptionRule.
 */
export interface GetNetworkFirewallPolicyDecryptionRuleArgs {
    /**
     * Name for the decryption rule, must be unique within the policy.
     */
    name: string;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: string;
}

/**
 * A collection of values returned by getNetworkFirewallPolicyDecryptionRule.
 */
export interface GetNetworkFirewallPolicyDecryptionRuleResult {
    /**
     * Action:
     * * NO_DECRYPT - Matching traffic is not decrypted.
     * * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.
     */
    readonly action: string;
    /**
     * Match criteria used in Decryption Rule used on the firewall policy rules.
     */
    readonly conditions: outputs.NetworkFirewall.GetNetworkFirewallPolicyDecryptionRuleCondition[];
    /**
     * The name of the decryption profile to use.
     */
    readonly decryptionProfile: string;
    readonly id: string;
    /**
     * Name for the decryption rule, must be unique within the policy.
     */
    readonly name: string;
    readonly networkFirewallPolicyId: string;
    /**
     * OCID of the Network Firewall Policy this decryption rule belongs to.
     */
    readonly parentResourceId: string;
    /**
     * An object which defines the position of the rule.
     */
    readonly positions: outputs.NetworkFirewall.GetNetworkFirewallPolicyDecryptionRulePosition[];
    readonly priorityOrder: string;
    /**
     * The name of a mapped secret. Its `type` must match that of the specified decryption profile.
     */
    readonly secret: string;
}
/**
 * This data source provides details about a specific Network Firewall Policy Decryption Rule resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get Decryption Rule by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyDecryptionRuleOutput(args: GetNetworkFirewallPolicyDecryptionRuleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNetworkFirewallPolicyDecryptionRuleResult> {
    return pulumi.output(args).apply((a: any) => getNetworkFirewallPolicyDecryptionRule(a, opts))
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyDecryptionRule.
 */
export interface GetNetworkFirewallPolicyDecryptionRuleOutputArgs {
    /**
     * Name for the decryption rule, must be unique within the policy.
     */
    name: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
}