// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Web App Firewall resource in Oracle Cloud Infrastructure Waf service.
 *
 * Gets a WebAppFirewall by OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWebAppFirewall = oci.Waf.getWebAppFirewall({
 *     webAppFirewallId: oci_waf_web_app_firewall.test_web_app_firewall.id,
 * });
 * ```
 */
export function getWebAppFirewall(args: GetWebAppFirewallArgs, opts?: pulumi.InvokeOptions): Promise<GetWebAppFirewallResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Waf/getWebAppFirewall:getWebAppFirewall", {
        "webAppFirewallId": args.webAppFirewallId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWebAppFirewall.
 */
export interface GetWebAppFirewallArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     */
    webAppFirewallId: string;
}

/**
 * A collection of values returned by getWebAppFirewall.
 */
export interface GetWebAppFirewallResult {
    /**
     * Type of the WebAppFirewall, as example LOAD_BALANCER.
     */
    readonly backendType: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * WebAppFirewall display name, can be renamed.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     */
    readonly lifecycleDetails: string;
    /**
     * LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppFirewallPolicy is attached to.
     */
    readonly loadBalancerId: string;
    /**
     * The current state of the WebAppFirewall.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the WebAppFirewall was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the WebAppFirewall was updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    readonly webAppFirewallId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppFirewallPolicy, which is attached to the resource.
     */
    readonly webAppFirewallPolicyId: string;
}

export function getWebAppFirewallOutput(args: GetWebAppFirewallOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetWebAppFirewallResult> {
    return pulumi.output(args).apply(a => getWebAppFirewall(a, opts))
}

/**
 * A collection of arguments for invoking getWebAppFirewall.
 */
export interface GetWebAppFirewallOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     */
    webAppFirewallId: pulumi.Input<string>;
}