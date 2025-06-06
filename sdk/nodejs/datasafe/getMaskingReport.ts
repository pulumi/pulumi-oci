// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Masking Report resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified masking report.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingReport = oci.DataSafe.getMaskingReport({
 *     maskingReportId: testMaskingReportOciDataSafeMaskingReport.id,
 * });
 * ```
 */
export function getMaskingReport(args: GetMaskingReportArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingReportResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getMaskingReport:getMaskingReport", {
        "maskingReportId": args.maskingReportId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingReport.
 */
export interface GetMaskingReportArgs {
    /**
     * The OCID of the masking report.
     */
    maskingReportId: string;
}

/**
 * A collection of values returned by getMaskingReport.
 */
export interface GetMaskingReportResult {
    /**
     * The OCID of the compartment that contains the masking report.
     */
    readonly compartmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates if the temporary tables created during the masking operation were dropped after masking.
     */
    readonly isDropTempTablesEnabled: boolean;
    /**
     * Indicates if redo logging was enabled during the masking operation.
     */
    readonly isRedoLoggingEnabled: boolean;
    /**
     * Indicates if statistics gathering was enabled during the masking operation.
     */
    readonly isRefreshStatsEnabled: boolean;
    /**
     * The OCID of the masking policy used.
     */
    readonly maskingPolicyId: string;
    readonly maskingReportId: string;
    /**
     * The status of the masking job.
     */
    readonly maskingStatus: string;
    /**
     * The OCID of the masking work request that resulted in this masking report.
     */
    readonly maskingWorkRequestId: string;
    /**
     * Indicates if parallel execution was enabled during the masking operation.
     */
    readonly parallelDegree: string;
    /**
     * Indicates how invalid objects were recompiled post the masking operation.
     */
    readonly recompile: string;
    /**
     * The current state of the masking report.
     */
    readonly state: string;
    /**
     * The OCID of the target database masked.
     */
    readonly targetId: string;
    /**
     * The date and time the masking report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The date and time data masking finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    readonly timeMaskingFinished: string;
    /**
     * The date and time data masking started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    readonly timeMaskingStarted: string;
    /**
     * The total number of masked columns.
     */
    readonly totalMaskedColumns: string;
    /**
     * The total number of unique objects (tables and editioning views) that contain the masked columns.
     */
    readonly totalMaskedObjects: string;
    /**
     * The total number of unique schemas that contain the masked columns.
     */
    readonly totalMaskedSchemas: string;
    /**
     * The total number of unique sensitive types associated with the masked columns.
     */
    readonly totalMaskedSensitiveTypes: string;
    /**
     * The total number of masked values.
     */
    readonly totalMaskedValues: string;
    /**
     * The total number of errors in post-masking script.
     */
    readonly totalPostMaskingScriptErrors: string;
    /**
     * The total number of errors in pre-masking script.
     */
    readonly totalPreMaskingScriptErrors: string;
}
/**
 * This data source provides details about a specific Masking Report resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified masking report.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingReport = oci.DataSafe.getMaskingReport({
 *     maskingReportId: testMaskingReportOciDataSafeMaskingReport.id,
 * });
 * ```
 */
export function getMaskingReportOutput(args: GetMaskingReportOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMaskingReportResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getMaskingReport:getMaskingReport", {
        "maskingReportId": args.maskingReportId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingReport.
 */
export interface GetMaskingReportOutputArgs {
    /**
     * The OCID of the masking report.
     */
    maskingReportId: pulumi.Input<string>;
}
