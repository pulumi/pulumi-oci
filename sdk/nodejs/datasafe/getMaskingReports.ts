// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Masking Reports in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of masking reports based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingReports = oci.DataSafe.getMaskingReports({
 *     compartmentId: compartmentId,
 *     accessLevel: maskingReportAccessLevel,
 *     compartmentIdInSubtree: maskingReportCompartmentIdInSubtree,
 *     maskingPolicyId: testMaskingPolicy.id,
 *     targetId: testTarget.id,
 * });
 * ```
 */
export function getMaskingReports(args: GetMaskingReportsArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingReportsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getMaskingReports:getMaskingReports", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "maskingPolicyId": args.maskingPolicyId,
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingReports.
 */
export interface GetMaskingReportsArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.DataSafe.GetMaskingReportsFilter[];
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
 * A collection of values returned by getMaskingReports.
 */
export interface GetMaskingReportsResult {
    readonly accessLevel?: string;
    /**
     * The OCID of the compartment that contains the masking report.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.DataSafe.GetMaskingReportsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the masking policy used.
     */
    readonly maskingPolicyId?: string;
    /**
     * The list of masking_report_collection.
     */
    readonly maskingReportCollections: outputs.DataSafe.GetMaskingReportsMaskingReportCollection[];
    /**
     * The OCID of the target database masked.
     */
    readonly targetId?: string;
}
/**
 * This data source provides the list of Masking Reports in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of masking reports based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingReports = oci.DataSafe.getMaskingReports({
 *     compartmentId: compartmentId,
 *     accessLevel: maskingReportAccessLevel,
 *     compartmentIdInSubtree: maskingReportCompartmentIdInSubtree,
 *     maskingPolicyId: testMaskingPolicy.id,
 *     targetId: testTarget.id,
 * });
 * ```
 */
export function getMaskingReportsOutput(args: GetMaskingReportsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMaskingReportsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getMaskingReports:getMaskingReports", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "maskingPolicyId": args.maskingPolicyId,
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingReports.
 */
export interface GetMaskingReportsOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetMaskingReportsFilterArgs>[]>;
    /**
     * A filter to return only the resources that match the specified masking policy OCID.
     */
    maskingPolicyId?: pulumi.Input<string>;
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: pulumi.Input<string>;
}
