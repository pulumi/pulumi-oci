// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Masking Policies in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of masking policies based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingPolicies = oci.DataSafe.getMaskingPolicies({
 *     compartmentId: compartmentId,
 *     accessLevel: maskingPolicyAccessLevel,
 *     compartmentIdInSubtree: maskingPolicyCompartmentIdInSubtree,
 *     displayName: maskingPolicyDisplayName,
 *     maskingPolicyId: testMaskingPolicy.id,
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     state: maskingPolicyState,
 *     targetId: testTarget.id,
 *     timeCreatedGreaterThanOrEqualTo: maskingPolicyTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: maskingPolicyTimeCreatedLessThan,
 * });
 * ```
 */
export function getMaskingPolicies(args: GetMaskingPoliciesArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingPoliciesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getMaskingPolicies:getMaskingPolicies", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "maskingPolicyId": args.maskingPolicyId,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "state": args.state,
        "targetId": args.targetId,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingPolicies.
 */
export interface GetMaskingPoliciesArgs {
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
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: string;
    filters?: inputs.DataSafe.GetMaskingPoliciesFilter[];
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
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: string;
    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedLessThan?: string;
}

/**
 * A collection of values returned by getMaskingPolicies.
 */
export interface GetMaskingPoliciesResult {
    readonly accessLevel?: string;
    /**
     * The OCID of the compartment that contains the masking policy.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The display name of the masking policy.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DataSafe.GetMaskingPoliciesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of masking_policy_collection.
     */
    readonly maskingPolicyCollections: outputs.DataSafe.GetMaskingPoliciesMaskingPolicyCollection[];
    readonly maskingPolicyId?: string;
    /**
     * The OCID of the sensitive data model that's used as the source of masking columns.
     */
    readonly sensitiveDataModelId?: string;
    /**
     * The current state of the masking policy.
     */
    readonly state?: string;
    /**
     * The OCID of the target database that's used as the source of masking columns.
     */
    readonly targetId?: string;
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
}
/**
 * This data source provides the list of Masking Policies in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of masking policies based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingPolicies = oci.DataSafe.getMaskingPolicies({
 *     compartmentId: compartmentId,
 *     accessLevel: maskingPolicyAccessLevel,
 *     compartmentIdInSubtree: maskingPolicyCompartmentIdInSubtree,
 *     displayName: maskingPolicyDisplayName,
 *     maskingPolicyId: testMaskingPolicy.id,
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     state: maskingPolicyState,
 *     targetId: testTarget.id,
 *     timeCreatedGreaterThanOrEqualTo: maskingPolicyTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: maskingPolicyTimeCreatedLessThan,
 * });
 * ```
 */
export function getMaskingPoliciesOutput(args: GetMaskingPoliciesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMaskingPoliciesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getMaskingPolicies:getMaskingPolicies", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "maskingPolicyId": args.maskingPolicyId,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "state": args.state,
        "targetId": args.targetId,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingPolicies.
 */
export interface GetMaskingPoliciesOutputArgs {
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
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetMaskingPoliciesFilterArgs>[]>;
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
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedLessThan?: pulumi.Input<string>;
}
