// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of published and staged applications of a Visual Builder Instance in Oracle Cloud Infrastructure Visual Builder service.
 *
 * Returns a list of published and staged applications of a Visual Builder instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVbInstanceApplications = oci.VisualBuilder.getVbInstanceApplications({
 *     vbInstanceId: oci_visual_builder_vb_instance.test_vb_instance.id,
 *     idcsOpenId: "idcs_open_id_value",
 * });
 * ```
 */
export function getVbInstanceApplications(args: GetVbInstanceApplicationsArgs, opts?: pulumi.InvokeOptions): Promise<GetVbInstanceApplicationsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:VisualBuilder/getVbInstanceApplications:getVbInstanceApplications", {
        "idcsOpenId": args.idcsOpenId,
        "vbInstanceId": args.vbInstanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVbInstanceApplications.
 */
export interface GetVbInstanceApplicationsArgs {
    /**
     * Encrypted IDCS Open ID token which allows access to Visual Builder REST apis
     */
    idcsOpenId?: string;
    /**
     * Unique Vb Instance identifier.
     */
    vbInstanceId: string;
}

/**
 * A collection of values returned by getVbInstanceApplications.
 */
export interface GetVbInstanceApplicationsResult {
    /**
     * The list of application_summary_collection.
     */
    readonly applicationSummaryCollections: outputs.VisualBuilder.GetVbInstanceApplicationsApplicationSummaryCollection[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly idcsOpenId?: string;
    readonly vbInstanceId: string;
}

export function getVbInstanceApplicationsOutput(args: GetVbInstanceApplicationsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetVbInstanceApplicationsResult> {
    return pulumi.output(args).apply(a => getVbInstanceApplications(a, opts))
}

/**
 * A collection of arguments for invoking getVbInstanceApplications.
 */
export interface GetVbInstanceApplicationsOutputArgs {
    /**
     * Encrypted IDCS Open ID token which allows access to Visual Builder REST apis
     */
    idcsOpenId?: pulumi.Input<string>;
    /**
     * Unique Vb Instance identifier.
     */
    vbInstanceId: pulumi.Input<string>;
}