// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Data Mask Rules in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a list of all DataMaskRule resources in the specified compartmentId (OCID) and its subcompartments.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataMaskRules = oci.CloudGuard.getDataMaskRules({
 *     compartmentId: compartmentId,
 *     accessLevel: dataMaskRuleAccessLevel,
 *     dataMaskRuleStatus: dataMaskRuleDataMaskRuleStatus,
 *     displayName: dataMaskRuleDisplayName,
 *     iamGroupId: testGroup.id,
 *     state: dataMaskRuleState,
 *     targetId: testTarget.id,
 *     targetType: dataMaskRuleTargetType,
 * });
 * ```
 */
export function getDataMaskRules(args: GetDataMaskRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetDataMaskRulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CloudGuard/getDataMaskRules:getDataMaskRules", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "dataMaskRuleStatus": args.dataMaskRuleStatus,
        "displayName": args.displayName,
        "filters": args.filters,
        "iamGroupId": args.iamGroupId,
        "state": args.state,
        "targetId": args.targetId,
        "targetType": args.targetType,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataMaskRules.
 */
export interface GetDataMaskRulesArgs {
    /**
     * Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * The status of the data mask rule
     */
    dataMaskRuleStatus?: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.CloudGuard.GetDataMaskRulesFilter[];
    /**
     * OCID of the IAM group
     */
    iamGroupId?: string;
    /**
     * The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     */
    state?: string;
    /**
     * OCID of the target
     */
    targetId?: string;
    /**
     * Type of target
     */
    targetType?: string;
}

/**
 * A collection of values returned by getDataMaskRules.
 */
export interface GetDataMaskRulesResult {
    readonly accessLevel?: string;
    /**
     * Compartment OCID where the resource is created
     */
    readonly compartmentId: string;
    /**
     * The list of data_mask_rule_collection.
     */
    readonly dataMaskRuleCollections: outputs.CloudGuard.GetDataMaskRulesDataMaskRuleCollection[];
    /**
     * The current status of the data mask rule
     */
    readonly dataMaskRuleStatus?: string;
    /**
     * Data mask rule display name
     */
    readonly displayName?: string;
    readonly filters?: outputs.CloudGuard.GetDataMaskRulesFilter[];
    /**
     * IAM Group ID associated with the data mask rule
     */
    readonly iamGroupId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current lifecycle state of the data mask rule
     */
    readonly state?: string;
    readonly targetId?: string;
    readonly targetType?: string;
}
/**
 * This data source provides the list of Data Mask Rules in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a list of all DataMaskRule resources in the specified compartmentId (OCID) and its subcompartments.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataMaskRules = oci.CloudGuard.getDataMaskRules({
 *     compartmentId: compartmentId,
 *     accessLevel: dataMaskRuleAccessLevel,
 *     dataMaskRuleStatus: dataMaskRuleDataMaskRuleStatus,
 *     displayName: dataMaskRuleDisplayName,
 *     iamGroupId: testGroup.id,
 *     state: dataMaskRuleState,
 *     targetId: testTarget.id,
 *     targetType: dataMaskRuleTargetType,
 * });
 * ```
 */
export function getDataMaskRulesOutput(args: GetDataMaskRulesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDataMaskRulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CloudGuard/getDataMaskRules:getDataMaskRules", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "dataMaskRuleStatus": args.dataMaskRuleStatus,
        "displayName": args.displayName,
        "filters": args.filters,
        "iamGroupId": args.iamGroupId,
        "state": args.state,
        "targetId": args.targetId,
        "targetType": args.targetType,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataMaskRules.
 */
export interface GetDataMaskRulesOutputArgs {
    /**
     * Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The status of the data mask rule
     */
    dataMaskRuleStatus?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CloudGuard.GetDataMaskRulesFilterArgs>[]>;
    /**
     * OCID of the IAM group
     */
    iamGroupId?: pulumi.Input<string>;
    /**
     * The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     */
    state?: pulumi.Input<string>;
    /**
     * OCID of the target
     */
    targetId?: pulumi.Input<string>;
    /**
     * Type of target
     */
    targetType?: pulumi.Input<string>;
}
