// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Protection Rules in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Gets the list of available protection rules for a WAAS policy. Use the `GetWafConfig` operation to view a list of currently configured protection rules for the Web Application Firewall, or use the `ListRecommendations` operation to get a list of recommended protection rules for the Web Application Firewall.
 * The list is sorted by `key`, in ascending order.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProtectionRules = oci.Waas.getProtectionRules({
 *     waasPolicyId: oci_waas_waas_policy.test_waas_policy.id,
 *     actions: _var.protection_rule_action,
 *     modSecurityRuleIds: oci_events_rule.test_rule.id,
 * });
 * ```
 */
export function getProtectionRules(args: GetProtectionRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetProtectionRulesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Waas/getProtectionRules:getProtectionRules", {
        "actions": args.actions,
        "filters": args.filters,
        "modSecurityRuleIds": args.modSecurityRuleIds,
        "waasPolicyId": args.waasPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getProtectionRules.
 */
export interface GetProtectionRulesArgs {
    /**
     * Filter rules using a list of actions.
     */
    actions?: string[];
    filters?: inputs.Waas.GetProtectionRulesFilter[];
    /**
     * Filter rules using a list of ModSecurity rule IDs.
     */
    modSecurityRuleIds?: string[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    waasPolicyId: string;
}

/**
 * A collection of values returned by getProtectionRules.
 */
export interface GetProtectionRulesResult {
    /**
     * The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
     */
    readonly actions?: string[];
    readonly filters?: outputs.Waas.GetProtectionRulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly modSecurityRuleIds?: string[];
    /**
     * The list of protection_rules.
     */
    readonly protectionRules: outputs.Waas.GetProtectionRulesProtectionRule[];
    readonly waasPolicyId: string;
}

export function getProtectionRulesOutput(args: GetProtectionRulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetProtectionRulesResult> {
    return pulumi.output(args).apply(a => getProtectionRules(a, opts))
}

/**
 * A collection of arguments for invoking getProtectionRules.
 */
export interface GetProtectionRulesOutputArgs {
    /**
     * Filter rules using a list of actions.
     */
    actions?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.Waas.GetProtectionRulesFilterArgs>[]>;
    /**
     * Filter rules using a list of ModSecurity rule IDs.
     */
    modSecurityRuleIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    waasPolicyId: pulumi.Input<string>;
}