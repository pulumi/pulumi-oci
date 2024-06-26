// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Fleet Crypto Analysis Results in Oracle Cloud Infrastructure Jms service.
 *
 * Lists the results of a Crypto event analysis.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetCryptoAnalysisResults = oci.Jms.getFleetCryptoAnalysisResults({
 *     fleetId: testFleet.id,
 *     aggregationMode: fleetCryptoAnalysisResultAggregationMode,
 *     managedInstanceId: testManagedInstance.id,
 *     timeEnd: fleetCryptoAnalysisResultTimeEnd,
 *     timeStart: fleetCryptoAnalysisResultTimeStart,
 * });
 * ```
 */
export function getFleetCryptoAnalysisResults(args: GetFleetCryptoAnalysisResultsArgs, opts?: pulumi.InvokeOptions): Promise<GetFleetCryptoAnalysisResultsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getFleetCryptoAnalysisResults:getFleetCryptoAnalysisResults", {
        "aggregationMode": args.aggregationMode,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "managedInstanceId": args.managedInstanceId,
        "timeEnd": args.timeEnd,
        "timeStart": args.timeStart,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetCryptoAnalysisResults.
 */
export interface GetFleetCryptoAnalysisResultsArgs {
    /**
     * The aggregation mode of the crypto event analysis result.
     */
    aggregationMode?: string;
    filters?: inputs.Jms.GetFleetCryptoAnalysisResultsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: string;
    /**
     * The Fleet-unique identifier of the related managed instance.
     */
    managedInstanceId?: string;
    /**
     * The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeEnd?: string;
    /**
     * The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeStart?: string;
}

/**
 * A collection of values returned by getFleetCryptoAnalysisResults.
 */
export interface GetFleetCryptoAnalysisResultsResult {
    /**
     * The result aggregation mode
     */
    readonly aggregationMode?: string;
    /**
     * The list of crypto_analysis_result_collection.
     */
    readonly cryptoAnalysisResultCollections: outputs.Jms.GetFleetCryptoAnalysisResultsCryptoAnalysisResultCollection[];
    readonly filters?: outputs.Jms.GetFleetCryptoAnalysisResultsFilter[];
    /**
     * The fleet OCID.
     */
    readonly fleetId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The managed instance OCID.
     */
    readonly managedInstanceId?: string;
    readonly timeEnd?: string;
    readonly timeStart?: string;
}
/**
 * This data source provides the list of Fleet Crypto Analysis Results in Oracle Cloud Infrastructure Jms service.
 *
 * Lists the results of a Crypto event analysis.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetCryptoAnalysisResults = oci.Jms.getFleetCryptoAnalysisResults({
 *     fleetId: testFleet.id,
 *     aggregationMode: fleetCryptoAnalysisResultAggregationMode,
 *     managedInstanceId: testManagedInstance.id,
 *     timeEnd: fleetCryptoAnalysisResultTimeEnd,
 *     timeStart: fleetCryptoAnalysisResultTimeStart,
 * });
 * ```
 */
export function getFleetCryptoAnalysisResultsOutput(args: GetFleetCryptoAnalysisResultsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetFleetCryptoAnalysisResultsResult> {
    return pulumi.output(args).apply((a: any) => getFleetCryptoAnalysisResults(a, opts))
}

/**
 * A collection of arguments for invoking getFleetCryptoAnalysisResults.
 */
export interface GetFleetCryptoAnalysisResultsOutputArgs {
    /**
     * The aggregation mode of the crypto event analysis result.
     */
    aggregationMode?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Jms.GetFleetCryptoAnalysisResultsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: pulumi.Input<string>;
    /**
     * The Fleet-unique identifier of the related managed instance.
     */
    managedInstanceId?: pulumi.Input<string>;
    /**
     * The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeEnd?: pulumi.Input<string>;
    /**
     * The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeStart?: pulumi.Input<string>;
}
