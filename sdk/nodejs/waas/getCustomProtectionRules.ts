// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Custom Protection Rules in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Gets a list of custom protection rules for the specified Web Application Firewall.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCustomProtectionRules = oci.Waas.getCustomProtectionRules({
 *     compartmentId: _var.compartment_id,
 *     displayNames: _var.custom_protection_rule_display_names,
 *     ids: _var.custom_protection_rule_ids,
 *     states: _var.custom_protection_rule_states,
 *     timeCreatedGreaterThanOrEqualTo: _var.custom_protection_rule_time_created_greater_than_or_equal_to,
 *     timeCreatedLessThan: _var.custom_protection_rule_time_created_less_than,
 * });
 * ```
 */
export function getCustomProtectionRules(args: GetCustomProtectionRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetCustomProtectionRulesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Waas/getCustomProtectionRules:getCustomProtectionRules", {
        "compartmentId": args.compartmentId,
        "displayNames": args.displayNames,
        "filters": args.filters,
        "ids": args.ids,
        "states": args.states,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getCustomProtectionRules.
 */
export interface GetCustomProtectionRulesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     */
    compartmentId: string;
    /**
     * Filter custom protection rules using a list of display names.
     */
    displayNames?: string[];
    filters?: inputs.Waas.GetCustomProtectionRulesFilter[];
    /**
     * Filter custom protection rules using a list of custom protection rule OCIDs.
     */
    ids?: string[];
    /**
     * Filter Custom Protection rules using a list of lifecycle states.
     */
    states?: string[];
    /**
     * A filter that matches Custom Protection rules created on or after the specified date-time.
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * A filter that matches custom protection rules created before the specified date-time.
     */
    timeCreatedLessThan?: string;
}

/**
 * A collection of values returned by getCustomProtectionRules.
 */
export interface GetCustomProtectionRulesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule's compartment.
     */
    readonly compartmentId: string;
    /**
     * The list of custom_protection_rules.
     */
    readonly customProtectionRules: outputs.Waas.GetCustomProtectionRulesCustomProtectionRule[];
    readonly displayNames?: string[];
    readonly filters?: outputs.Waas.GetCustomProtectionRulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly ids?: string[];
    readonly states?: string[];
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
}

export function getCustomProtectionRulesOutput(args: GetCustomProtectionRulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetCustomProtectionRulesResult> {
    return pulumi.output(args).apply(a => getCustomProtectionRules(a, opts))
}

/**
 * A collection of arguments for invoking getCustomProtectionRules.
 */
export interface GetCustomProtectionRulesOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Filter custom protection rules using a list of display names.
     */
    displayNames?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.Waas.GetCustomProtectionRulesFilterArgs>[]>;
    /**
     * Filter custom protection rules using a list of custom protection rule OCIDs.
     */
    ids?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Filter Custom Protection rules using a list of lifecycle states.
     */
    states?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter that matches Custom Protection rules created on or after the specified date-time.
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * A filter that matches custom protection rules created before the specified date-time.
     */
    timeCreatedLessThan?: pulumi.Input<string>;
}