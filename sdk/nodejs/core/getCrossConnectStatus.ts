// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Cross Connect Status resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the status of the specified cross-connect.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCrossConnectStatus = oci.Core.getCrossConnectStatus({
 *     crossConnectId: oci_core_cross_connect.test_cross_connect.id,
 * });
 * ```
 */
export function getCrossConnectStatus(args: GetCrossConnectStatusArgs, opts?: pulumi.InvokeOptions): Promise<GetCrossConnectStatusResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getCrossConnectStatus:getCrossConnectStatus", {
        "crossConnectId": args.crossConnectId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCrossConnectStatus.
 */
export interface GetCrossConnectStatusArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect.
     */
    crossConnectId: string;
}

/**
 * A collection of values returned by getCrossConnectStatus.
 */
export interface GetCrossConnectStatusResult {
    /**
     * The OCID of the cross-connect.
     */
    readonly crossConnectId: string;
    /**
     * Encryption status of the CrossConnect
     */
    readonly encryptionStatus: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Whether Oracle's side of the interface is up or down.
     */
    readonly interfaceState: string;
    /**
     * The light level of the cross-connect (in dBm).  Example: `14.0`
     */
    readonly lightLevelIndBm: number;
    /**
     * Status indicator corresponding to the light level.
     * * **NO_LIGHT:** No measurable light
     * * **LOW_WARN:** There's measurable light but it's too low
     * * **HIGH_WARN:** Light level is too high
     * * **BAD:** There's measurable light but the signal-to-noise ratio is bad
     * * **GOOD:** Good light level
     */
    readonly lightLevelIndicator: string;
}

export function getCrossConnectStatusOutput(args: GetCrossConnectStatusOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetCrossConnectStatusResult> {
    return pulumi.output(args).apply(a => getCrossConnectStatus(a, opts))
}

/**
 * A collection of arguments for invoking getCrossConnectStatus.
 */
export interface GetCrossConnectStatusOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect.
     */
    crossConnectId: pulumi.Input<string>;
}