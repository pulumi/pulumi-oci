// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Fusion Environment Status resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Gets the status of a Fusion environment identified by its OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentStatus = oci.Functions.getFusionEnvironmentStatus({
 *     fusionEnvironmentId: oci_fusion_apps_fusion_environment.test_fusion_environment.id,
 * });
 * ```
 */
export function getFusionEnvironmentStatus(args: GetFusionEnvironmentStatusArgs, opts?: pulumi.InvokeOptions): Promise<GetFusionEnvironmentStatusResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Functions/getFusionEnvironmentStatus:getFusionEnvironmentStatus", {
        "fusionEnvironmentId": args.fusionEnvironmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentStatus.
 */
export interface GetFusionEnvironmentStatusArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: string;
}

/**
 * A collection of values returned by getFusionEnvironmentStatus.
 */
export interface GetFusionEnvironmentStatusResult {
    readonly fusionEnvironmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The data plane status of FusionEnvironment.
     */
    readonly status: string;
}

export function getFusionEnvironmentStatusOutput(args: GetFusionEnvironmentStatusOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetFusionEnvironmentStatusResult> {
    return pulumi.output(args).apply(a => getFusionEnvironmentStatus(a, opts))
}

/**
 * A collection of arguments for invoking getFusionEnvironmentStatus.
 */
export interface GetFusionEnvironmentStatusOutputArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
}