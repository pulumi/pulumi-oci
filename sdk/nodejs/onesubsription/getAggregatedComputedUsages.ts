// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Aggregated Computed Usages in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This is a collection API which returns a list of aggregated computed usage details (there can be multiple Parent Products under a given SubID each of which is represented under Subscription Service Line # in SPM).
 */
export function getAggregatedComputedUsages(args: GetAggregatedComputedUsagesArgs, opts?: pulumi.InvokeOptions): Promise<GetAggregatedComputedUsagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OneSubsription/getAggregatedComputedUsages:getAggregatedComputedUsages", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "grouping": args.grouping,
        "parentProduct": args.parentProduct,
        "subscriptionId": args.subscriptionId,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getAggregatedComputedUsages.
 */
export interface GetAggregatedComputedUsagesArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    filters?: inputs.OneSubsription.GetAggregatedComputedUsagesFilter[];
    /**
     * Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
     */
    grouping?: string;
    /**
     * Product part number for subscribed service line, called parent product.
     */
    parentProduct?: string;
    /**
     * Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
     */
    subscriptionId: string;
    /**
     * Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
     */
    timeFrom: string;
    /**
     * Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
     */
    timeTo: string;
}

/**
 * A collection of values returned by getAggregatedComputedUsages.
 */
export interface GetAggregatedComputedUsagesResult {
    /**
     * Aggregation of computed usages for the subscribed service.
     */
    readonly aggregatedComputedUsages: outputs.OneSubsription.GetAggregatedComputedUsagesAggregatedComputedUsage[];
    readonly compartmentId: string;
    readonly filters?: outputs.OneSubsription.GetAggregatedComputedUsagesFilter[];
    readonly grouping?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Product description
     */
    readonly parentProduct?: string;
    /**
     * Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM
     */
    readonly subscriptionId: string;
    readonly timeFrom: string;
    readonly timeTo: string;
}
/**
 * This data source provides the list of Aggregated Computed Usages in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This is a collection API which returns a list of aggregated computed usage details (there can be multiple Parent Products under a given SubID each of which is represented under Subscription Service Line # in SPM).
 */
export function getAggregatedComputedUsagesOutput(args: GetAggregatedComputedUsagesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAggregatedComputedUsagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OneSubsription/getAggregatedComputedUsages:getAggregatedComputedUsages", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "grouping": args.grouping,
        "parentProduct": args.parentProduct,
        "subscriptionId": args.subscriptionId,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getAggregatedComputedUsages.
 */
export interface GetAggregatedComputedUsagesOutputArgs {
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OneSubsription.GetAggregatedComputedUsagesFilterArgs>[]>;
    /**
     * Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
     */
    grouping?: pulumi.Input<string>;
    /**
     * Product part number for subscribed service line, called parent product.
     */
    parentProduct?: pulumi.Input<string>;
    /**
     * Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
     */
    subscriptionId: pulumi.Input<string>;
    /**
     * Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
     */
    timeFrom: pulumi.Input<string>;
    /**
     * Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
     */
    timeTo: pulumi.Input<string>;
}
