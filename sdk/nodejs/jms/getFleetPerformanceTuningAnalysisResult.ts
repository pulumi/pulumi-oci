// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Fleet Performance Tuning Analysis Result resource in Oracle Cloud Infrastructure Jms service.
 *
 * Retrieve metadata of the Performance Tuning Analysis result.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetPerformanceTuningAnalysisResult = oci.Jms.getFleetPerformanceTuningAnalysisResult({
 *     fleetId: oci_jms_fleet.test_fleet.id,
 *     performanceTuningAnalysisResultId: oci_apm_synthetics_result.test_result.id,
 * });
 * ```
 */
export function getFleetPerformanceTuningAnalysisResult(args: GetFleetPerformanceTuningAnalysisResultArgs, opts?: pulumi.InvokeOptions): Promise<GetFleetPerformanceTuningAnalysisResultResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getFleetPerformanceTuningAnalysisResult:getFleetPerformanceTuningAnalysisResult", {
        "fleetId": args.fleetId,
        "performanceTuningAnalysisResultId": args.performanceTuningAnalysisResultId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetPerformanceTuningAnalysisResult.
 */
export interface GetFleetPerformanceTuningAnalysisResultArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: string;
    /**
     * The OCID of the performance tuning analysis result.
     */
    performanceTuningAnalysisResultId: string;
}

/**
 * A collection of values returned by getFleetPerformanceTuningAnalysisResult.
 */
export interface GetFleetPerformanceTuningAnalysisResultResult {
    /**
     * The OCID of the application for which the report has been generated.
     */
    readonly applicationId: string;
    /**
     * The internal identifier of the application installation for which the report has been generated.
     */
    readonly applicationInstallationId: string;
    /**
     * The installation path of the application for which the report has been generated.
     */
    readonly applicationInstallationPath: string;
    /**
     * The name of the application for which the report has been generated.
     */
    readonly applicationName: string;
    /**
     * The Object Storage bucket name of this analysis result.
     */
    readonly bucket: string;
    /**
     * The fleet OCID.
     */
    readonly fleetId: string;
    /**
     * The hostname of the managed instance.
     */
    readonly hostName: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The managed instance OCID.
     */
    readonly managedInstanceId: string;
    /**
     * The Object Storage namespace of this analysis result.
     */
    readonly namespace: string;
    /**
     * The Object Storage object name of this analysis result.
     */
    readonly object: string;
    readonly performanceTuningAnalysisResultId: string;
    /**
     * Result of the analysis based on whether warnings have been found or not.
     */
    readonly result: string;
    /**
     * The time the result is compiled.
     */
    readonly timeCreated: string;
    /**
     * The time the JFR capture finished.
     */
    readonly timeFinished: string;
    /**
     * The time the JFR capture started.
     */
    readonly timeStarted: string;
    /**
     * Total number of warnings reported by the analysis.
     */
    readonly warningCount: number;
    /**
     * The OCID of the work request to start the analysis.
     */
    readonly workRequestId: string;
}
/**
 * This data source provides details about a specific Fleet Performance Tuning Analysis Result resource in Oracle Cloud Infrastructure Jms service.
 *
 * Retrieve metadata of the Performance Tuning Analysis result.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetPerformanceTuningAnalysisResult = oci.Jms.getFleetPerformanceTuningAnalysisResult({
 *     fleetId: oci_jms_fleet.test_fleet.id,
 *     performanceTuningAnalysisResultId: oci_apm_synthetics_result.test_result.id,
 * });
 * ```
 */
export function getFleetPerformanceTuningAnalysisResultOutput(args: GetFleetPerformanceTuningAnalysisResultOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetFleetPerformanceTuningAnalysisResultResult> {
    return pulumi.output(args).apply((a: any) => getFleetPerformanceTuningAnalysisResult(a, opts))
}

/**
 * A collection of arguments for invoking getFleetPerformanceTuningAnalysisResult.
 */
export interface GetFleetPerformanceTuningAnalysisResultOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: pulumi.Input<string>;
    /**
     * The OCID of the performance tuning analysis result.
     */
    performanceTuningAnalysisResultId: pulumi.Input<string>;
}