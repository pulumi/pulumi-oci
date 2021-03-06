// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Masking Analytic resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets consolidated masking analytics data based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingAnalytic = oci.DataSafe.getMaskingAnalytic({
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.masking_analytic_compartment_id_in_subtree,
 *     groupBy: _var.masking_analytic_group_by,
 *     maskingPolicyId: oci_data_safe_masking_policy.test_masking_policy.id,
 *     targetId: oci_cloud_guard_target.test_target.id,
 * });
 * ```
 */
export function getMaskingAnalytic(args: GetMaskingAnalyticArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingAnalyticResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataSafe/getMaskingAnalytic:getMaskingAnalytic", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "groupBy": args.groupBy,
        "maskingPolicyId": args.maskingPolicyId,
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingAnalytic.
 */
export interface GetMaskingAnalyticArgs {
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * Attribute by which the masking analytics data should be grouped.
     */
    groupBy?: string;
    /**
     * A filter to return only the resources that match the specified masking policy OCID.
     */
    maskingPolicyId?: string;
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: string;
}

/**
 * A collection of values returned by getMaskingAnalytic.
 */
export interface GetMaskingAnalyticResult {
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly groupBy?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * An array of masking analytics summary objects.
     */
    readonly items: outputs.DataSafe.GetMaskingAnalyticItem[];
    readonly maskingPolicyId?: string;
    /**
     * The OCID of the target database.
     */
    readonly targetId?: string;
}

export function getMaskingAnalyticOutput(args: GetMaskingAnalyticOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMaskingAnalyticResult> {
    return pulumi.output(args).apply(a => getMaskingAnalytic(a, opts))
}

/**
 * A collection of arguments for invoking getMaskingAnalytic.
 */
export interface GetMaskingAnalyticOutputArgs {
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * Attribute by which the masking analytics data should be grouped.
     */
    groupBy?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that match the specified masking policy OCID.
     */
    maskingPolicyId?: pulumi.Input<string>;
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: pulumi.Input<string>;
}
