// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sdm Masking Policy Difference Difference Columns in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of columns of a SDM masking policy difference resource based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSdmMaskingPolicyDifferenceDifferenceColumns = oci.DataSafe.getSdmMaskingPolicyDifferenceDifferenceColumns({
 *     sdmMaskingPolicyDifferenceId: testSdmMaskingPolicyDifference.id,
 *     columnNames: sdmMaskingPolicyDifferenceDifferenceColumnColumnName,
 *     differenceType: sdmMaskingPolicyDifferenceDifferenceColumnDifferenceType,
 *     objects: sdmMaskingPolicyDifferenceDifferenceColumnObject,
 *     plannedAction: sdmMaskingPolicyDifferenceDifferenceColumnPlannedAction,
 *     schemaNames: sdmMaskingPolicyDifferenceDifferenceColumnSchemaName,
 *     syncStatus: sdmMaskingPolicyDifferenceDifferenceColumnSyncStatus,
 * });
 * ```
 */
export function getSdmMaskingPolicyDifferenceDifferenceColumns(args: GetSdmMaskingPolicyDifferenceDifferenceColumnsArgs, opts?: pulumi.InvokeOptions): Promise<GetSdmMaskingPolicyDifferenceDifferenceColumnsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSdmMaskingPolicyDifferenceDifferenceColumns:getSdmMaskingPolicyDifferenceDifferenceColumns", {
        "columnNames": args.columnNames,
        "differenceType": args.differenceType,
        "filters": args.filters,
        "objects": args.objects,
        "plannedAction": args.plannedAction,
        "schemaNames": args.schemaNames,
        "sdmMaskingPolicyDifferenceId": args.sdmMaskingPolicyDifferenceId,
        "syncStatus": args.syncStatus,
    }, opts);
}

/**
 * A collection of arguments for invoking getSdmMaskingPolicyDifferenceDifferenceColumns.
 */
export interface GetSdmMaskingPolicyDifferenceDifferenceColumnsArgs {
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: string[];
    /**
     * A filter to return only the SDM masking policy difference columns that match the specified difference type
     */
    differenceType?: string;
    filters?: inputs.DataSafe.GetSdmMaskingPolicyDifferenceDifferenceColumnsFilter[];
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: string[];
    /**
     * A filter to return only the SDM masking policy difference columns that match the specified planned action.
     */
    plannedAction?: string;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: string[];
    /**
     * The OCID of the SDM masking policy difference.
     */
    sdmMaskingPolicyDifferenceId: string;
    /**
     * A filter to return the SDM masking policy difference columns based on the value of their syncStatus attribute.
     */
    syncStatus?: string;
}

/**
 * A collection of values returned by getSdmMaskingPolicyDifferenceDifferenceColumns.
 */
export interface GetSdmMaskingPolicyDifferenceDifferenceColumnsResult {
    /**
     * The name of the difference column.
     */
    readonly columnNames?: string[];
    /**
     * The type of the SDM masking policy difference column. It can be one of the following three types: NEW: A new sensitive column in the sensitive data model that is not in the masking policy. DELETED: A column that is present in the masking policy but has been deleted from the sensitive data model. MODIFIED: A column that is present in the masking policy as well as the sensitive data model but some of its attributes have been modified.
     */
    readonly differenceType?: string;
    readonly filters?: outputs.DataSafe.GetSdmMaskingPolicyDifferenceDifferenceColumnsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The database object that contains the difference column.
     */
    readonly objects?: string[];
    /**
     * Specifies how to process the difference column. It's set to SYNC by default. Use the PatchSdmMaskingPolicyDifferenceColumns operation to update this attribute. You can choose one of the following options: SYNC: To sync the difference column and update the masking policy to reflect the changes. NO_SYNC: To not sync the difference column so that it doesn't change the masking policy. After specifying the planned action, you can use the ApplySdmMaskingPolicyDifference operation to automatically process the difference columns.
     */
    readonly plannedAction?: string;
    /**
     * The database schema that contains the difference column.
     */
    readonly schemaNames?: string[];
    /**
     * The list of sdm_masking_policy_difference_column_collection.
     */
    readonly sdmMaskingPolicyDifferenceColumnCollections: outputs.DataSafe.GetSdmMaskingPolicyDifferenceDifferenceColumnsSdmMaskingPolicyDifferenceColumnCollection[];
    readonly sdmMaskingPolicyDifferenceId: string;
    /**
     * Indicates if the difference column has been processed. Use GetDifferenceColumn operation to  track whether the difference column has already been processed and applied to the masking policy.
     */
    readonly syncStatus?: string;
}
/**
 * This data source provides the list of Sdm Masking Policy Difference Difference Columns in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of columns of a SDM masking policy difference resource based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSdmMaskingPolicyDifferenceDifferenceColumns = oci.DataSafe.getSdmMaskingPolicyDifferenceDifferenceColumns({
 *     sdmMaskingPolicyDifferenceId: testSdmMaskingPolicyDifference.id,
 *     columnNames: sdmMaskingPolicyDifferenceDifferenceColumnColumnName,
 *     differenceType: sdmMaskingPolicyDifferenceDifferenceColumnDifferenceType,
 *     objects: sdmMaskingPolicyDifferenceDifferenceColumnObject,
 *     plannedAction: sdmMaskingPolicyDifferenceDifferenceColumnPlannedAction,
 *     schemaNames: sdmMaskingPolicyDifferenceDifferenceColumnSchemaName,
 *     syncStatus: sdmMaskingPolicyDifferenceDifferenceColumnSyncStatus,
 * });
 * ```
 */
export function getSdmMaskingPolicyDifferenceDifferenceColumnsOutput(args: GetSdmMaskingPolicyDifferenceDifferenceColumnsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSdmMaskingPolicyDifferenceDifferenceColumnsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSdmMaskingPolicyDifferenceDifferenceColumns:getSdmMaskingPolicyDifferenceDifferenceColumns", {
        "columnNames": args.columnNames,
        "differenceType": args.differenceType,
        "filters": args.filters,
        "objects": args.objects,
        "plannedAction": args.plannedAction,
        "schemaNames": args.schemaNames,
        "sdmMaskingPolicyDifferenceId": args.sdmMaskingPolicyDifferenceId,
        "syncStatus": args.syncStatus,
    }, opts);
}

/**
 * A collection of arguments for invoking getSdmMaskingPolicyDifferenceDifferenceColumns.
 */
export interface GetSdmMaskingPolicyDifferenceDifferenceColumnsOutputArgs {
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the SDM masking policy difference columns that match the specified difference type
     */
    differenceType?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSdmMaskingPolicyDifferenceDifferenceColumnsFilterArgs>[]>;
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the SDM masking policy difference columns that match the specified planned action.
     */
    plannedAction?: pulumi.Input<string>;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the SDM masking policy difference.
     */
    sdmMaskingPolicyDifferenceId: pulumi.Input<string>;
    /**
     * A filter to return the SDM masking policy difference columns based on the value of their syncStatus attribute.
     */
    syncStatus?: pulumi.Input<string>;
}
