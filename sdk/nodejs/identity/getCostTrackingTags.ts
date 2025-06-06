// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Cost Tracking Tags in Oracle Cloud Infrastructure Identity service.
 *
 * Lists all the tags enabled for cost-tracking in the specified tenancy. For information about
 * cost-tracking tags, see [Using Cost-tracking Tags](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#costs).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCostTrackingTags = oci.Identity.getCostTrackingTags({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getCostTrackingTags(args: GetCostTrackingTagsArgs, opts?: pulumi.InvokeOptions): Promise<GetCostTrackingTagsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getCostTrackingTags:getCostTrackingTags", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getCostTrackingTags.
 */
export interface GetCostTrackingTagsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: string;
    filters?: inputs.Identity.GetCostTrackingTagsFilter[];
}

/**
 * A collection of values returned by getCostTrackingTags.
 */
export interface GetCostTrackingTagsResult {
    /**
     * The OCID of the compartment that contains the tag definition.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Identity.GetCostTrackingTagsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of tags.
     */
    readonly tags: outputs.Identity.GetCostTrackingTagsTag[];
}
/**
 * This data source provides the list of Cost Tracking Tags in Oracle Cloud Infrastructure Identity service.
 *
 * Lists all the tags enabled for cost-tracking in the specified tenancy. For information about
 * cost-tracking tags, see [Using Cost-tracking Tags](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#costs).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCostTrackingTags = oci.Identity.getCostTrackingTags({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getCostTrackingTagsOutput(args: GetCostTrackingTagsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetCostTrackingTagsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getCostTrackingTags:getCostTrackingTags", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getCostTrackingTags.
 */
export interface GetCostTrackingTagsOutputArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Identity.GetCostTrackingTagsFilterArgs>[]>;
}
