// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Network Firewall Policy Service resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get Service by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyService(args: GetNetworkFirewallPolicyServiceArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkFirewallPolicyServiceResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkFirewall/getNetworkFirewallPolicyService:getNetworkFirewallPolicyService", {
        "name": args.name,
        "networkFirewallPolicyId": args.networkFirewallPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyService.
 */
export interface GetNetworkFirewallPolicyServiceArgs {
    /**
     * Name of the service.
     */
    name: string;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: string;
}

/**
 * A collection of values returned by getNetworkFirewallPolicyService.
 */
export interface GetNetworkFirewallPolicyServiceResult {
    readonly id: string;
    /**
     * Name of the service.
     */
    readonly name: string;
    readonly networkFirewallPolicyId: string;
    /**
     * OCID of the Network Firewall Policy this service belongs to.
     */
    readonly parentResourceId: string;
    /**
     * List of port-ranges used.
     */
    readonly portRanges: outputs.NetworkFirewall.GetNetworkFirewallPolicyServicePortRange[];
    /**
     * Describes the type of Service.
     */
    readonly type: string;
}
/**
 * This data source provides details about a specific Network Firewall Policy Service resource in Oracle Cloud Infrastructure Network Firewall service.
 *
 * Get Service by the given name in the context of network firewall policy.
 */
export function getNetworkFirewallPolicyServiceOutput(args: GetNetworkFirewallPolicyServiceOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNetworkFirewallPolicyServiceResult> {
    return pulumi.output(args).apply((a: any) => getNetworkFirewallPolicyService(a, opts))
}

/**
 * A collection of arguments for invoking getNetworkFirewallPolicyService.
 */
export interface GetNetworkFirewallPolicyServiceOutputArgs {
    /**
     * Name of the service.
     */
    name: pulumi.Input<string>;
    /**
     * Unique Network Firewall Policy identifier
     */
    networkFirewallPolicyId: pulumi.Input<string>;
}