// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of User Assessment Password Expiry Date Analytics in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of count of the users with password expiry dates in next 30 days, between next 30-90 days, and beyond 90 days based on specified user assessment.
 * It internally uses the aforementioned userAnalytics api.
 *
 * When you perform the ListPasswordExpiryDateAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
 * parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
 * permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
 * root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
 * compartmentId, then "Not Authorized" is returned.
 *
 * To use ListPasswordExpiryDateAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
 * set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUserAssessmentPasswordExpiryDateAnalytics = oci.DataSafe.getUserAssessmentPasswordExpiryDateAnalytics({
 *     userAssessmentId: testUserAssessment.id,
 *     accessLevel: userAssessmentPasswordExpiryDateAnalyticAccessLevel,
 *     compartmentIdInSubtree: userAssessmentPasswordExpiryDateAnalyticCompartmentIdInSubtree,
 *     timePasswordExpiryLessThan: userAssessmentPasswordExpiryDateAnalyticTimePasswordExpiryLessThan,
 *     userCategory: userAssessmentPasswordExpiryDateAnalyticUserCategory,
 * });
 * ```
 */
export function getUserAssessmentPasswordExpiryDateAnalytics(args: GetUserAssessmentPasswordExpiryDateAnalyticsArgs, opts?: pulumi.InvokeOptions): Promise<GetUserAssessmentPasswordExpiryDateAnalyticsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getUserAssessmentPasswordExpiryDateAnalytics:getUserAssessmentPasswordExpiryDateAnalytics", {
        "accessLevel": args.accessLevel,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "timePasswordExpiryLessThan": args.timePasswordExpiryLessThan,
        "userAssessmentId": args.userAssessmentId,
        "userCategory": args.userCategory,
    }, opts);
}

/**
 * A collection of arguments for invoking getUserAssessmentPasswordExpiryDateAnalytics.
 */
export interface GetUserAssessmentPasswordExpiryDateAnalyticsArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.DataSafe.GetUserAssessmentPasswordExpiryDateAnalyticsFilter[];
    /**
     * A filter to return users whose password expiry date in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
     */
    timePasswordExpiryLessThan?: string;
    /**
     * The OCID of the user assessment.
     */
    userAssessmentId: string;
    /**
     * A filter to return only items that match the specified user category.
     */
    userCategory?: string;
}

/**
 * A collection of values returned by getUserAssessmentPasswordExpiryDateAnalytics.
 */
export interface GetUserAssessmentPasswordExpiryDateAnalyticsResult {
    readonly accessLevel?: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.DataSafe.GetUserAssessmentPasswordExpiryDateAnalyticsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly timePasswordExpiryLessThan?: string;
    /**
     * The list of user_aggregations.
     */
    readonly userAggregations: outputs.DataSafe.GetUserAssessmentPasswordExpiryDateAnalyticsUserAggregation[];
    readonly userAssessmentId: string;
    readonly userCategory?: string;
}
/**
 * This data source provides the list of User Assessment Password Expiry Date Analytics in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of count of the users with password expiry dates in next 30 days, between next 30-90 days, and beyond 90 days based on specified user assessment.
 * It internally uses the aforementioned userAnalytics api.
 *
 * When you perform the ListPasswordExpiryDateAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
 * parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has READ
 * permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
 * root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
 * compartmentId, then "Not Authorized" is returned.
 *
 * To use ListPasswordExpiryDateAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
 * set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUserAssessmentPasswordExpiryDateAnalytics = oci.DataSafe.getUserAssessmentPasswordExpiryDateAnalytics({
 *     userAssessmentId: testUserAssessment.id,
 *     accessLevel: userAssessmentPasswordExpiryDateAnalyticAccessLevel,
 *     compartmentIdInSubtree: userAssessmentPasswordExpiryDateAnalyticCompartmentIdInSubtree,
 *     timePasswordExpiryLessThan: userAssessmentPasswordExpiryDateAnalyticTimePasswordExpiryLessThan,
 *     userCategory: userAssessmentPasswordExpiryDateAnalyticUserCategory,
 * });
 * ```
 */
export function getUserAssessmentPasswordExpiryDateAnalyticsOutput(args: GetUserAssessmentPasswordExpiryDateAnalyticsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetUserAssessmentPasswordExpiryDateAnalyticsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getUserAssessmentPasswordExpiryDateAnalytics:getUserAssessmentPasswordExpiryDateAnalytics", {
        "accessLevel": args.accessLevel,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "timePasswordExpiryLessThan": args.timePasswordExpiryLessThan,
        "userAssessmentId": args.userAssessmentId,
        "userCategory": args.userCategory,
    }, opts);
}

/**
 * A collection of arguments for invoking getUserAssessmentPasswordExpiryDateAnalytics.
 */
export interface GetUserAssessmentPasswordExpiryDateAnalyticsOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetUserAssessmentPasswordExpiryDateAnalyticsFilterArgs>[]>;
    /**
     * A filter to return users whose password expiry date in the database is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). **Example:** 2016-12-19T16:39:57.600Z
     */
    timePasswordExpiryLessThan?: pulumi.Input<string>;
    /**
     * The OCID of the user assessment.
     */
    userAssessmentId: pulumi.Input<string>;
    /**
     * A filter to return only items that match the specified user category.
     */
    userCategory?: pulumi.Input<string>;
}
