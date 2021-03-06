// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Suppressions in Oracle Cloud Infrastructure Email service.
 *
 * Gets a list of suppressed recipient email addresses for a user. The
 * `compartmentId` for suppressions must be a tenancy OCID. The returned list
 * is sorted by creation time in descending order.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSuppressions = oci.Email.getSuppressions({
 *     compartmentId: _var.tenancy_ocid,
 *     emailAddress: _var.suppression_email_address,
 *     timeCreatedGreaterThanOrEqualTo: _var.suppression_time_created_greater_than_or_equal_to,
 *     timeCreatedLessThan: _var.suppression_time_created_less_than,
 * });
 * ```
 */
export function getSuppressions(args: GetSuppressionsArgs, opts?: pulumi.InvokeOptions): Promise<GetSuppressionsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Email/getSuppressions:getSuppressions", {
        "compartmentId": args.compartmentId,
        "emailAddress": args.emailAddress,
        "filters": args.filters,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSuppressions.
 */
export interface GetSuppressionsArgs {
    /**
     * The OCID for the compartment.
     */
    compartmentId: string;
    /**
     * The email address of the suppression.
     */
    emailAddress?: string;
    filters?: inputs.Email.GetSuppressionsFilter[];
    /**
     * Search for suppressions that were created within a specific date range, using this parameter to specify the earliest creation date for the returned list (inclusive). Specifying this parameter without the corresponding `timeCreatedLessThan` parameter will retrieve suppressions created from the given `timeCreatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * Search for suppressions that were created within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all suppressions created before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreatedLessThan?: string;
}

/**
 * A collection of values returned by getSuppressions.
 */
export interface GetSuppressionsResult {
    /**
     * The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     */
    readonly compartmentId: string;
    /**
     * The email address of the suppression.
     */
    readonly emailAddress?: string;
    readonly filters?: outputs.Email.GetSuppressionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of suppressions.
     */
    readonly suppressions: outputs.Email.GetSuppressionsSuppression[];
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
}

export function getSuppressionsOutput(args: GetSuppressionsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSuppressionsResult> {
    return pulumi.output(args).apply(a => getSuppressions(a, opts))
}

/**
 * A collection of arguments for invoking getSuppressions.
 */
export interface GetSuppressionsOutputArgs {
    /**
     * The OCID for the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The email address of the suppression.
     */
    emailAddress?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Email.GetSuppressionsFilterArgs>[]>;
    /**
     * Search for suppressions that were created within a specific date range, using this parameter to specify the earliest creation date for the returned list (inclusive). Specifying this parameter without the corresponding `timeCreatedLessThan` parameter will retrieve suppressions created from the given `timeCreatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for suppressions that were created within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all suppressions created before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreatedLessThan?: pulumi.Input<string>;
}
