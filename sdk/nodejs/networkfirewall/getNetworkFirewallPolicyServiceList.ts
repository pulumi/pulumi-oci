// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Network Firewall Policy Service List resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get ServiceList by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyServiceList(args: GetNetworkFirewallPolicyServiceListArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkFirewallPolicyServiceListResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkFirewall/getNetworkFirewallPolicyServiceList:getNetworkFirewallPolicyServiceList", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyServiceList.
 */
export interface GetNetworkFirewallPolicyServiceListArgs {
    /**
     * Name of the service Group.
     */
    name: string;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: string;
}

/**
 * A collection of values returned by getNetworkFirewallPolicyServiceList.
 */
export interface GetNetworkFirewallPolicyServiceListResult {
    readonly id: string;
    /**
     * Name of the service Group.
     */
    readonly name: string;
    readonly networkFirewallPolicyId: string;
    /**
     * OCID of the Network Firewall Policy this serviceList belongs to.
     */
    readonly parentResourceId: string;
    /**
     * List of services in the group.
     */
    readonly services: string[];
    /**
     * Count of total services in the given service List.
     */
    readonly totalServices: number;
}
/**
 * This data source provides details about a specific Network Firewall Policy Service List resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get ServiceList by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyServiceListOutput(args: GetNetworkFirewallPolicyServiceListOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNetworkFirewallPolicyServiceListResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyServiceList:getNetworkFirewallPolicyServiceList", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyServiceList.
 */
export interface GetNetworkFirewallPolicyServiceListOutputArgs {
    /**
     * Name of the service Group.
     */
    name: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
}
