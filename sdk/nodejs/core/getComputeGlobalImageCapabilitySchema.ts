// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Compute Global Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified Compute Global Image Capability Schema
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComputeGlobalImageCapabilitySchema = oci.Core.getComputeGlobalImageCapabilitySchema({
 *     computeGlobalImageCapabilitySchemaId: oci_core_compute_global_image_capability_schema.test_compute_global_image_capability_schema.id,
 * });
 * ```
 */
export function getComputeGlobalImageCapabilitySchema(args: GetComputeGlobalImageCapabilitySchemaArgs, opts?: pulumi.InvokeOptions): Promise<GetComputeGlobalImageCapabilitySchemaResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getComputeGlobalImageCapabilitySchema:getComputeGlobalImageCapabilitySchema", {
        "computeGlobalImageCapabilitySchemaId": args.computeGlobalImageCapabilitySchemaId,
    }, opts);
}

/**
 * A collection of arguments for invoking getComputeGlobalImageCapabilitySchema.
 */
export interface GetComputeGlobalImageCapabilitySchemaArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
     */
    computeGlobalImageCapabilitySchemaId: string;
}

/**
 * A collection of values returned by getComputeGlobalImageCapabilitySchema.
 */
export interface GetComputeGlobalImageCapabilitySchemaResult {
    /**
     * The OCID of the compartment containing the compute global image capability schema
     */
    readonly compartmentId: string;
    readonly computeGlobalImageCapabilitySchemaId: string;
    /**
     * The name of the global capabilities version resource that is considered the current version.
     */
    readonly currentVersionName: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The date and time the compute global image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
}

export function getComputeGlobalImageCapabilitySchemaOutput(args: GetComputeGlobalImageCapabilitySchemaOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetComputeGlobalImageCapabilitySchemaResult> {
    return pulumi.output(args).apply(a => getComputeGlobalImageCapabilitySchema(a, opts))
}

/**
 * A collection of arguments for invoking getComputeGlobalImageCapabilitySchema.
 */
export interface GetComputeGlobalImageCapabilitySchemaOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
     */
    computeGlobalImageCapabilitySchemaId: pulumi.Input<string>;
}