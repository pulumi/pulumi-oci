// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Network Firewall Policy Application Group resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get ApplicationGroup by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyApplicationGroup(args: GetNetworkFirewallPolicyApplicationGroupArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkFirewallPolicyApplicationGroupResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkFirewall/getNetworkFirewallPolicyApplicationGroup:getNetworkFirewallPolicyApplicationGroup", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyApplicationGroup.
 */
export interface GetNetworkFirewallPolicyApplicationGroupArgs {
    /**
     * Name of the application Group.
     */
    name: string;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: string;
}

/**
 * A collection of values returned by getNetworkFirewallPolicyApplicationGroup.
 */
export interface GetNetworkFirewallPolicyApplicationGroupResult {
    /**
     * List of apps in the group.
     */
    readonly apps: string[];
    readonly id: string;
    /**
     * Name of the application Group.
     */
    readonly name: string;
    readonly networkFirewallPolicyId: string;
    /**
     * OCID of the Network Firewall Policy this application group belongs to.
     */
    readonly parentResourceId: string;
    /**
     * Count of total applications in the given application group.
     */
    readonly totalApps: number;
}
/**
 * This data source provides details about a specific Network Firewall Policy Application Group resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get ApplicationGroup by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyApplicationGroupOutput(args: GetNetworkFirewallPolicyApplicationGroupOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNetworkFirewallPolicyApplicationGroupResult> {
    return pulumi.output(args).apply((a: any) => getNetworkFirewallPolicyApplicationGroup(a, opts))
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyApplicationGroup.
 */
export interface GetNetworkFirewallPolicyApplicationGroupOutputArgs {
    /**
     * Name of the application Group.
     */
    name: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
}