// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
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
 *     vbInstanceId: testVbInstance.id,
 *     idcsOpenId: "idcs_open_id_value",
 * });
 * ```
 */
export function getVbInstanceApplications(args: GetVbInstanceApplicationsArgs, opts?: pulumi.InvokeOptions): Promise<GetVbInstanceApplicationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
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
 *     vbInstanceId: testVbInstance.id,
 *     idcsOpenId: "idcs_open_id_value",
 * });
 * ```
 */
export function getVbInstanceApplicationsOutput(args: GetVbInstanceApplicationsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetVbInstanceApplicationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:VisualBuilder/getVbInstanceApplications:getVbInstanceApplications", {
        "idcsOpenId": args.idcsOpenId,
        "vbInstanceId": args.vbInstanceId,
    }, opts);
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
