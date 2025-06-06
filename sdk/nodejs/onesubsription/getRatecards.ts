// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Ratecards in Oracle Cloud Infrastructure Onesubscription service.
 *
 * List API that returns all ratecards for given Subscription Id and Account ID (if provided) and
 * for a particular date range
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRatecards = oci.OneSubsription.getRatecards({
 *     compartmentId: compartmentId,
 *     subscriptionId: testSubscription.id,
 *     partNumber: ratecardPartNumber,
 *     timeFrom: ratecardTimeFrom,
 *     timeTo: ratecardTimeTo,
 * });
 * ```
 */
export function getRatecards(args: GetRatecardsArgs, opts?: pulumi.InvokeOptions): Promise<GetRatecardsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OneSubsription/getRatecards:getRatecards", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "partNumber": args.partNumber,
        "subscriptionId": args.subscriptionId,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getRatecards.
 */
export interface GetRatecardsArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    filters?: inputs.OneSubsription.GetRatecardsFilter[];
    /**
     * This param is used to get the rate card(s) filterd by the partNumber
     */
    partNumber?: string;
    /**
     * Line level Subscription Id
     */
    subscriptionId: string;
    /**
     * This param is used to get the rate card(s) whose effective start date starts on or after a particular date
     */
    timeFrom?: string;
    /**
     * This param is used to get the rate card(s) whose effective end date ends on or before a particular date
     */
    timeTo?: string;
}

/**
 * A collection of values returned by getRatecards.
 */
export interface GetRatecardsResult {
    readonly compartmentId: string;
    readonly filters?: outputs.OneSubsription.GetRatecardsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Product part numner
     */
    readonly partNumber?: string;
    /**
     * The list of rate_cards.
     */
    readonly rateCards: outputs.OneSubsription.GetRatecardsRateCard[];
    readonly subscriptionId: string;
    readonly timeFrom?: string;
    readonly timeTo?: string;
}
/**
 * This data source provides the list of Ratecards in Oracle Cloud Infrastructure Onesubscription service.
 *
 * List API that returns all ratecards for given Subscription Id and Account ID (if provided) and
 * for a particular date range
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRatecards = oci.OneSubsription.getRatecards({
 *     compartmentId: compartmentId,
 *     subscriptionId: testSubscription.id,
 *     partNumber: ratecardPartNumber,
 *     timeFrom: ratecardTimeFrom,
 *     timeTo: ratecardTimeTo,
 * });
 * ```
 */
export function getRatecardsOutput(args: GetRatecardsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetRatecardsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OneSubsription/getRatecards:getRatecards", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "partNumber": args.partNumber,
        "subscriptionId": args.subscriptionId,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getRatecards.
 */
export interface GetRatecardsOutputArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OneSubsription.GetRatecardsFilterArgs>[]>;
    /**
     * This param is used to get the rate card(s) filterd by the partNumber
     */
    partNumber?: pulumi.Input<string>;
    /**
     * Line level Subscription Id
     */
    subscriptionId: pulumi.Input<string>;
    /**
     * This param is used to get the rate card(s) whose effective start date starts on or after a particular date
     */
    timeFrom?: pulumi.Input<string>;
    /**
     * This param is used to get the rate card(s) whose effective end date ends on or before a particular date
     */
    timeTo?: pulumi.Input<string>;
}
