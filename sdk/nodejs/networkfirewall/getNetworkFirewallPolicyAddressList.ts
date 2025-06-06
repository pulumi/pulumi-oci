// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Network Firewall Policy Address List resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get Address List by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyAddressList(args: GetNetworkFirewallPolicyAddressListArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkFirewallPolicyAddressListResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkFirewall/getNetworkFirewallPolicyAddressList:getNetworkFirewallPolicyAddressList", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyAddressList.
 */
export interface GetNetworkFirewallPolicyAddressListArgs {
    /**
     * Unique name to identify the group of addresses to be used in the policy rules.
     */
    name: string;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: string;
}

/**
 * A collection of values returned by getNetworkFirewallPolicyAddressList.
 */
export interface GetNetworkFirewallPolicyAddressListResult {
    /**
     * List of addresses.
     */
    readonly addresses: string[];
    readonly id: string;
    /**
     * Unique name to identify the group of addresses to be used in the policy rules.
     */
    readonly name: string;
    readonly networkFirewallPolicyId: string;
    /**
     * OCID of the Network Firewall Policy this Address List belongs to.
     */
    readonly parentResourceId: string;
    /**
     * Count of total Addresses in the AddressList
     */
    readonly totalAddresses: number;
    /**
     * Type of address List.
     */
    readonly type: string;
}
/**
 * This data source provides details about a specific Network Firewall Policy Address List resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get Address List by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyAddressListOutput(args: GetNetworkFirewallPolicyAddressListOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNetworkFirewallPolicyAddressListResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:NetworkFirewall/getNetworkFirewallPolicyAddressList:getNetworkFirewallPolicyAddressList", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyAddressList.
 */
export interface GetNetworkFirewallPolicyAddressListOutputArgs {
    /**
     * Unique name to identify the group of addresses to be used in the policy rules.
     */
    name: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
}
