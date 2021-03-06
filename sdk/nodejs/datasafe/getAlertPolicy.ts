// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Alert Policy resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of alert policy by its ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAlertPolicy = oci.DataSafe.getAlertPolicy({
 *     alertPolicyId: oci_data_safe_alert_policy.test_alert_policy.id,
 * });
 * ```
 */
export function getAlertPolicy(args: GetAlertPolicyArgs, opts?: pulumi.InvokeOptions): Promise<GetAlertPolicyResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataSafe/getAlertPolicy:getAlertPolicy", {
        "alertPolicyId": args.alertPolicyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAlertPolicy.
 */
export interface GetAlertPolicyArgs {
    /**
     * The OCID of the alert policy.
     */
    alertPolicyId: string;
}

/**
 * A collection of values returned by getAlertPolicy.
 */
export interface GetAlertPolicyResult {
    readonly alertPolicyId: string;
    /**
     * Indicates the Data Safe feature to which the alert policy belongs.
     */
    readonly alertPolicyType: string;
    /**
     * The OCID of the compartment that contains the alert policy.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The description of the alert policy.
     */
    readonly description: string;
    /**
     * The display name of the alert policy.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates if the alert policy is user-defined (true) or pre-defined (false).
     */
    readonly isUserDefined: boolean;
    /**
     * Severity level of the alert raised by this policy.
     */
    readonly severity: string;
    /**
     * The current state of the alert.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * Creation date and time of the alert policy, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * Last date and time the alert policy was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeUpdated: string;
}

export function getAlertPolicyOutput(args: GetAlertPolicyOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAlertPolicyResult> {
    return pulumi.output(args).apply(a => getAlertPolicy(a, opts))
}

/**
 * A collection of arguments for invoking getAlertPolicy.
 */
export interface GetAlertPolicyOutputArgs {
    /**
     * The OCID of the alert policy.
     */
    alertPolicyId: pulumi.Input<string>;
}
