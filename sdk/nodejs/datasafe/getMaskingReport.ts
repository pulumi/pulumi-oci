// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
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
 *     maskingReportId: oci_data_safe_masking_report.test_masking_report.id,
 * });
 * ```
 */
export function getMaskingReport(args: GetMaskingReportArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingReportResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
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
     * The OCID of the masking policy used.
     */
    readonly maskingPolicyId: string;
    readonly maskingReportId: string;
    /**
     * The OCID of the masking work request that resulted in this masking report.
     */
    readonly maskingWorkRequestId: string;
    /**
     * The OCID of the target database masked.
     */
    readonly targetId: string;
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
}

export function getMaskingReportOutput(args: GetMaskingReportOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMaskingReportResult> {
    return pulumi.output(args).apply(a => getMaskingReport(a, opts))
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