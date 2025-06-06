// *** WARNING: this file was generated by pulumi-language-nodejs. ***
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
 *     fusionEnvironmentId: testFusionEnvironment.id,
 * });
 * ```
 */
export function getFusionEnvironmentStatus(args: GetFusionEnvironmentStatusArgs, opts?: pulumi.InvokeOptions): Promise<GetFusionEnvironmentStatusResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
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
 *     fusionEnvironmentId: testFusionEnvironment.id,
 * });
 * ```
 */
export function getFusionEnvironmentStatusOutput(args: GetFusionEnvironmentStatusOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFusionEnvironmentStatusResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Functions/getFusionEnvironmentStatus:getFusionEnvironmentStatus", {
        "fusionEnvironmentId": args.fusionEnvironmentId,
    }, opts);
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
