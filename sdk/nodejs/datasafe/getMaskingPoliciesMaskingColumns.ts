// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Masking Policies Masking Columns in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of masking columns present in the specified masking policy and based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingPoliciesMaskingColumns = oci.DataSafe.getMaskingPoliciesMaskingColumns({
 *     maskingPolicyId: oci_data_safe_masking_policy.test_masking_policy.id,
 *     columnNames: _var.masking_policies_masking_column_column_name,
 *     dataTypes: _var.masking_policies_masking_column_data_type,
 *     isMaskingEnabled: _var.masking_policies_masking_column_is_masking_enabled,
 *     isSeedRequired: _var.masking_policies_masking_column_is_seed_required,
 *     maskingColumnGroups: _var.masking_policies_masking_column_masking_column_group,
 *     maskingColumnLifecycleState: _var.masking_policies_masking_column_masking_column_lifecycle_state,
 *     objects: _var.masking_policies_masking_column_object,
 *     objectTypes: _var.masking_policies_masking_column_object_type,
 *     schemaNames: _var.masking_policies_masking_column_schema_name,
 *     sensitiveTypeId: oci_data_safe_sensitive_type.test_sensitive_type.id,
 *     timeCreatedGreaterThanOrEqualTo: _var.masking_policies_masking_column_time_created_greater_than_or_equal_to,
 *     timeCreatedLessThan: _var.masking_policies_masking_column_time_created_less_than,
 *     timeUpdatedGreaterThanOrEqualTo: _var.masking_policies_masking_column_time_updated_greater_than_or_equal_to,
 *     timeUpdatedLessThan: _var.masking_policies_masking_column_time_updated_less_than,
 * });
 * ```
 */
export function getMaskingPoliciesMaskingColumns(args: GetMaskingPoliciesMaskingColumnsArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingPoliciesMaskingColumnsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataSafe/getMaskingPoliciesMaskingColumns:getMaskingPoliciesMaskingColumns", {
        "columnNames": args.columnNames,
        "dataTypes": args.dataTypes,
        "filters": args.filters,
        "isMaskingEnabled": args.isMaskingEnabled,
        "isSeedRequired": args.isSeedRequired,
        "maskingColumnGroups": args.maskingColumnGroups,
        "maskingColumnLifecycleState": args.maskingColumnLifecycleState,
        "maskingPolicyId": args.maskingPolicyId,
        "objectTypes": args.objectTypes,
        "objects": args.objects,
        "schemaNames": args.schemaNames,
        "sensitiveTypeId": args.sensitiveTypeId,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "timeUpdatedGreaterThanOrEqualTo": args.timeUpdatedGreaterThanOrEqualTo,
        "timeUpdatedLessThan": args.timeUpdatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingPoliciesMaskingColumns.
 */
export interface GetMaskingPoliciesMaskingColumnsArgs {
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: string[];
    /**
     * A filter to return only resources that match the specified data types.
     */
    dataTypes?: string[];
    filters?: inputs.DataSafe.GetMaskingPoliciesMaskingColumnsFilter[];
    /**
     * A filter to return the masking column resources based on the value of their isMaskingEnabled attribute. A value of true returns only those columns for which masking is enabled. A value of false returns only those columns for which masking is disabled. Omitting this parameter returns all the masking columns in a masking policy.
     */
    isMaskingEnabled?: boolean;
    /**
     * A filter to return masking columns based on whether the assigned masking formats need a seed value for masking. A value of true returns those masking columns that are using  Deterministic Encryption or Deterministic Substitution masking format.
     */
    isSeedRequired?: boolean;
    /**
     * A filter to return only the resources that match the specified masking column group.
     */
    maskingColumnGroups?: string[];
    /**
     * A filter to return only the resources that match the specified lifecycle states.
     */
    maskingColumnLifecycleState?: string;
    /**
     * The OCID of the masking policy.
     */
    maskingPolicyId: string;
    /**
     * A filter to return only items related to a specific object type.
     */
    objectTypes?: string[];
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: string[];
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: string[];
    /**
     * A filter to return only items related to a specific sensitive type OCID.
     */
    sensitiveTypeId?: string;
    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreatedLessThan?: string;
    /**
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedGreaterThanOrEqualTo?: string;
    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedLessThan?: string;
}

/**
 * A collection of values returned by getMaskingPoliciesMaskingColumns.
 */
export interface GetMaskingPoliciesMaskingColumnsResult {
    /**
     * The name of the substitution column.
     */
    readonly columnNames?: string[];
    /**
     * The data type of the masking column.
     */
    readonly dataTypes?: string[];
    readonly filters?: outputs.DataSafe.GetMaskingPoliciesMaskingColumnsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates if data masking is enabled for the masking column.
     */
    readonly isMaskingEnabled?: boolean;
    readonly isSeedRequired?: boolean;
    /**
     * The list of masking_column_collection.
     */
    readonly maskingColumnCollections: outputs.DataSafe.GetMaskingPoliciesMaskingColumnsMaskingColumnCollection[];
    /**
     * The group of the masking column. All the columns in a group are masked together to ensure  that the masked data across these columns continue to retain the same logical relationship.  For more details, check <a href=https://docs.oracle.com/en/cloud/paas/data-safe/udscs/group-masking1.html#GUID-755056B9-9540-48C0-9491-262A44A85037>Group Masking in the Data Safe documentation.</a>
     */
    readonly maskingColumnGroups?: string[];
    readonly maskingColumnLifecycleState?: string;
    /**
     * The OCID of the masking policy that contains the masking column.
     */
    readonly maskingPolicyId: string;
    /**
     * The type of the object that contains the database column.
     */
    readonly objectTypes?: string[];
    /**
     * The name of the object (table or editioning view) that contains the database column.
     */
    readonly objects?: string[];
    /**
     * The name of the schema that contains the database column.
     */
    readonly schemaNames?: string[];
    /**
     * The OCID of the sensitive type associated with the masking column.
     */
    readonly sensitiveTypeId?: string;
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
    readonly timeUpdatedGreaterThanOrEqualTo?: string;
    readonly timeUpdatedLessThan?: string;
}

export function getMaskingPoliciesMaskingColumnsOutput(args: GetMaskingPoliciesMaskingColumnsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMaskingPoliciesMaskingColumnsResult> {
    return pulumi.output(args).apply(a => getMaskingPoliciesMaskingColumns(a, opts))
}

/**
 * A collection of arguments for invoking getMaskingPoliciesMaskingColumns.
 */
export interface GetMaskingPoliciesMaskingColumnsOutputArgs {
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only resources that match the specified data types.
     */
    dataTypes?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetMaskingPoliciesMaskingColumnsFilterArgs>[]>;
    /**
     * A filter to return the masking column resources based on the value of their isMaskingEnabled attribute. A value of true returns only those columns for which masking is enabled. A value of false returns only those columns for which masking is disabled. Omitting this parameter returns all the masking columns in a masking policy.
     */
    isMaskingEnabled?: pulumi.Input<boolean>;
    /**
     * A filter to return masking columns based on whether the assigned masking formats need a seed value for masking. A value of true returns those masking columns that are using  Deterministic Encryption or Deterministic Substitution masking format.
     */
    isSeedRequired?: pulumi.Input<boolean>;
    /**
     * A filter to return only the resources that match the specified masking column group.
     */
    maskingColumnGroups?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the resources that match the specified lifecycle states.
     */
    maskingColumnLifecycleState?: pulumi.Input<string>;
    /**
     * The OCID of the masking policy.
     */
    maskingPolicyId: pulumi.Input<string>;
    /**
     * A filter to return only items related to a specific object type.
     */
    objectTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific sensitive type OCID.
     */
    sensitiveTypeId?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreatedLessThan?: pulumi.Input<string>;
    /**
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedLessThan?: pulumi.Input<string>;
}