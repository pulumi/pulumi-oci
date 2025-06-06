// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Network Firewall Policy Application Groups in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Returns a list of ApplicationGroups for the policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkFirewallPolicyApplicationGroups = oci.NetworkFirewall.getNetworkFirewallPolicyApplicationGroups({
 *     networkFirewallPolicyId: testNetworkFirewallPolicy.id,
 *     displayName: networkFirewallPolicyApplicationGroupDisplayName,
 * });
 * ```
 */
export function getNetworkFirewallPolicyApplicationGroups(args: GetNetworkFirewallPolicyApplicationGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkFirewallPolicyApplicationGroupsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkFirewall/getNetworkFirewallPolicyApplicationGroups:getNetworkFirewallPolicyApplicationGroups", {
        "displayName": args.displayName,
        "filters": args.filters,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyApplicationGroups.
 */
export interface GetNetworkFirewallPolicyApplicationGroupsArgs {
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.NetworkFirewall.GetNetworkFirewallPolicyApplicationGroupsFilter[];
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: string;
}

/**
 * A collection of values returned by getNetworkFirewallPolicyApplicationGroups.
 */
export interface GetNetworkFirewallPolicyApplicationGroupsResult {
    /**
     * The list of application_group_summary_collection.
     */
    readonly applicationGroupSummaryCollections: outputs.NetworkFirewall.GetNetworkFirewallPolicyApplicationGroupsApplicationGroupSummaryCollection[];
    readonly displayName?: string;
    readonly filters?: outputs.NetworkFirewall.GetNetworkFirewallPolicyApplicationGroupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly networkFirewallPolicyId: string;
}
/**
 * This data source provides the list of Network Firewall Policy Application Groups in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Returns a list of ApplicationGroups for the policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkFirewallPolicyApplicationGroups = oci.NetworkFirewall.getNetworkFirewallPolicyApplicationGroups({
 *     networkFirewallPolicyId: testNetworkFirewallPolicy.id,
 *     displayName: networkFirewallPolicyApplicationGroupDisplayName,
 * });
 * ```
 */
export function getNetworkFirewallPolicyApplicationGroupsOutput(args: GetNetworkFirewallPolicyApplicationGroupsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNetworkFirewallPolicyApplicationGroupsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyApplicationGroups:getNetworkFirewallPolicyApplicationGroups", {
        "displayName": args.displayName,
        "filters": args.filters,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyApplicationGroups.
 */
export interface GetNetworkFirewallPolicyApplicationGroupsOutputArgs {
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.NetworkFirewall.GetNetworkFirewallPolicyApplicationGroupsFilterArgs>[]>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
}
