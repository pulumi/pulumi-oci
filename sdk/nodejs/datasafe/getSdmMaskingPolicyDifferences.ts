// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sdm Masking Policy Differences in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of SDM and masking policy difference resources based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSdmMaskingPolicyDifferences = oci.DataSafe.getSdmMaskingPolicyDifferences({
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.sdm_masking_policy_difference_compartment_id_in_subtree,
 *     differenceAccessLevel: _var.sdm_masking_policy_difference_difference_access_level,
 *     displayName: _var.sdm_masking_policy_difference_display_name,
 *     maskingPolicyId: oci_data_safe_masking_policy.test_masking_policy.id,
 *     sensitiveDataModelId: oci_data_safe_sensitive_data_model.test_sensitive_data_model.id,
 *     state: _var.sdm_masking_policy_difference_state,
 * });
 * ```
 */
export function getSdmMaskingPolicyDifferences(args: GetSdmMaskingPolicyDifferencesArgs, opts?: pulumi.InvokeOptions): Promise<GetSdmMaskingPolicyDifferencesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSdmMaskingPolicyDifferences:getSdmMaskingPolicyDifferences", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "differenceAccessLevel": args.differenceAccessLevel,
        "displayName": args.displayName,
        "filters": args.filters,
        "maskingPolicyId": args.maskingPolicyId,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getSdmMaskingPolicyDifferences.
 */
export interface GetSdmMaskingPolicyDifferencesArgs {
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
     */
    differenceAccessLevel?: string;
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: string;
    filters?: inputs.DataSafe.GetSdmMaskingPolicyDifferencesFilter[];
    /**
     * A filter to return only the resources that match the specified masking policy OCID.
     */
    maskingPolicyId?: string;
    /**
     * A filter to return only the resources that match the specified sensitive data model OCID.
     */
    sensitiveDataModelId?: string;
    /**
     * A filter to return only the resources that match the specified lifecycle states.
     */
    state?: string;
}

/**
 * A collection of values returned by getSdmMaskingPolicyDifferences.
 */
export interface GetSdmMaskingPolicyDifferencesResult {
    /**
     * The OCID of the compartment that contains the SDM masking policy difference.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly differenceAccessLevel?: string;
    /**
     * The display name of the SDM masking policy difference.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DataSafe.GetSdmMaskingPolicyDifferencesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the masking policy associated with the SDM masking policy difference.
     */
    readonly maskingPolicyId?: string;
    /**
     * The list of sdm_masking_policy_difference_collection.
     */
    readonly sdmMaskingPolicyDifferenceCollections: outputs.DataSafe.GetSdmMaskingPolicyDifferencesSdmMaskingPolicyDifferenceCollection[];
    /**
     * The OCID of the sensitive data model associated with the SDM masking policy difference.
     */
    readonly sensitiveDataModelId?: string;
    /**
     * The current state of the SDM masking policy difference.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Sdm Masking Policy Differences in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of SDM and masking policy difference resources based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSdmMaskingPolicyDifferences = oci.DataSafe.getSdmMaskingPolicyDifferences({
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.sdm_masking_policy_difference_compartment_id_in_subtree,
 *     differenceAccessLevel: _var.sdm_masking_policy_difference_difference_access_level,
 *     displayName: _var.sdm_masking_policy_difference_display_name,
 *     maskingPolicyId: oci_data_safe_masking_policy.test_masking_policy.id,
 *     sensitiveDataModelId: oci_data_safe_sensitive_data_model.test_sensitive_data_model.id,
 *     state: _var.sdm_masking_policy_difference_state,
 * });
 * ```
 */
export function getSdmMaskingPolicyDifferencesOutput(args: GetSdmMaskingPolicyDifferencesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSdmMaskingPolicyDifferencesResult> {
    return pulumi.output(args).apply((a: any) => getSdmMaskingPolicyDifferences(a, opts))
}

/**
 * A collection of arguments for invoking getSdmMaskingPolicyDifferences.
 */
export interface GetSdmMaskingPolicyDifferencesOutputArgs {
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
     */
    differenceAccessLevel?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSdmMaskingPolicyDifferencesFilterArgs>[]>;
    /**
     * A filter to return only the resources that match the specified masking policy OCID.
     */
    maskingPolicyId?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that match the specified sensitive data model OCID.
     */
    sensitiveDataModelId?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that match the specified lifecycle states.
     */
    state?: pulumi.Input<string>;
}