// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Fusion Environment Data Masking Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Gets a DataMaskingActivity by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentDataMaskingActivity = oci.Functions.getFusionEnvironmentDataMaskingActivity({
 *     dataMaskingActivityId: oci_fusion_apps_data_masking_activity.test_data_masking_activity.id,
 *     fusionEnvironmentId: oci_fusion_apps_fusion_environment.test_fusion_environment.id,
 * });
 * ```
 */
export function getFusionEnvironmentDataMaskingActivity(args: GetFusionEnvironmentDataMaskingActivityArgs, opts?: pulumi.InvokeOptions): Promise<GetFusionEnvironmentDataMaskingActivityResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Functions/getFusionEnvironmentDataMaskingActivity:getFusionEnvironmentDataMaskingActivity", {
        "dataMaskingActivityId": args.dataMaskingActivityId,
        "fusionEnvironmentId": args.fusionEnvironmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentDataMaskingActivity.
 */
export interface GetFusionEnvironmentDataMaskingActivityArgs {
    /**
     * Unique DataMasking run identifier.
     */
    dataMaskingActivityId: string;
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: string;
}

/**
 * A collection of values returned by getFusionEnvironmentDataMaskingActivity.
 */
export interface GetFusionEnvironmentDataMaskingActivityResult {
    readonly dataMaskingActivityId: string;
    /**
     * Fusion Environment Identifier.
     */
    readonly fusionEnvironmentId: string;
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id: string;
    readonly isResumeDataMasking: boolean;
    /**
     * The current state of the DataMaskingActivity.
     */
    readonly state: string;
    /**
     * The time the data masking activity ended. An RFC3339 formatted datetime string.
     */
    readonly timeMaskingFinish: string;
    /**
     * The time the data masking activity started. An RFC3339 formatted datetime string.
     */
    readonly timeMaskingStart: string;
}

export function getFusionEnvironmentDataMaskingActivityOutput(args: GetFusionEnvironmentDataMaskingActivityOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetFusionEnvironmentDataMaskingActivityResult> {
    return pulumi.output(args).apply(a => getFusionEnvironmentDataMaskingActivity(a, opts))
}

/**
 * A collection of arguments for invoking getFusionEnvironmentDataMaskingActivity.
 */
export interface GetFusionEnvironmentDataMaskingActivityOutputArgs {
    /**
     * Unique DataMasking run identifier.
     */
    dataMaskingActivityId: pulumi.Input<string>;
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
}