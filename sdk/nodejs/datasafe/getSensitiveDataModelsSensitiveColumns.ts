// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sensitive Data Models Sensitive Columns in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of sensitive columns present in the specified sensitive data model based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveDataModelsSensitiveColumns = oci.DataSafe.getSensitiveDataModelsSensitiveColumns({
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     columnGroup: sensitiveDataModelsSensitiveColumnColumnGroup,
 *     columnNames: sensitiveDataModelsSensitiveColumnColumnName,
 *     dataTypes: sensitiveDataModelsSensitiveColumnDataType,
 *     isCaseInSensitive: sensitiveDataModelsSensitiveColumnIsCaseInSensitive,
 *     objects: sensitiveDataModelsSensitiveColumnObject,
 *     objectTypes: sensitiveDataModelsSensitiveColumnObjectType,
 *     parentColumnKeys: sensitiveDataModelsSensitiveColumnParentColumnKey,
 *     relationTypes: sensitiveDataModelsSensitiveColumnRelationType,
 *     schemaNames: sensitiveDataModelsSensitiveColumnSchemaName,
 *     sensitiveColumnLifecycleState: sensitiveDataModelsSensitiveColumnSensitiveColumnLifecycleState,
 *     sensitiveTypeIds: testSensitiveType.id,
 *     statuses: sensitiveDataModelsSensitiveColumnStatus,
 *     timeCreatedGreaterThanOrEqualTo: sensitiveDataModelsSensitiveColumnTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: sensitiveDataModelsSensitiveColumnTimeCreatedLessThan,
 *     timeUpdatedGreaterThanOrEqualTo: sensitiveDataModelsSensitiveColumnTimeUpdatedGreaterThanOrEqualTo,
 *     timeUpdatedLessThan: sensitiveDataModelsSensitiveColumnTimeUpdatedLessThan,
 * });
 * ```
 */
export function getSensitiveDataModelsSensitiveColumns(args: GetSensitiveDataModelsSensitiveColumnsArgs, opts?: pulumi.InvokeOptions): Promise<GetSensitiveDataModelsSensitiveColumnsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSensitiveDataModelsSensitiveColumns:getSensitiveDataModelsSensitiveColumns", {
        "columnGroup": args.columnGroup,
        "columnNames": args.columnNames,
        "dataTypes": args.dataTypes,
        "filters": args.filters,
        "isCaseInSensitive": args.isCaseInSensitive,
        "objectTypes": args.objectTypes,
        "objects": args.objects,
        "parentColumnKeys": args.parentColumnKeys,
        "relationTypes": args.relationTypes,
        "schemaNames": args.schemaNames,
        "sensitiveColumnLifecycleState": args.sensitiveColumnLifecycleState,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "sensitiveTypeIds": args.sensitiveTypeIds,
        "statuses": args.statuses,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "timeUpdatedGreaterThanOrEqualTo": args.timeUpdatedGreaterThanOrEqualTo,
        "timeUpdatedLessThan": args.timeUpdatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSensitiveDataModelsSensitiveColumns.
 */
export interface GetSensitiveDataModelsSensitiveColumnsArgs {
    /**
     * A filter to return only the sensitive columns that belong to the specified column group.
     */
    columnGroup?: string;
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: string[];
    /**
     * A filter to return only the resources that match the specified data types.
     */
    dataTypes?: string[];
    filters?: inputs.DataSafe.GetSensitiveDataModelsSensitiveColumnsFilter[];
    /**
     * A boolean flag indicating whether the search should be case-insensitive. The search is case-sensitive by default. Set this parameter to true to do case-insensitive search.
     */
    isCaseInSensitive?: boolean;
    /**
     * A filter to return only items related to a specific object type.
     */
    objectTypes?: string[];
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: string[];
    /**
     * A filter to return only the sensitive columns that are children of one of the columns identified by the specified keys.
     */
    parentColumnKeys?: string[];
    /**
     * A filter to return sensitive columns based on their relationship with their parent columns. If set to NONE, it returns the sensitive columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
     */
    relationTypes?: string[];
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: string[];
    /**
     * Filters the sensitive column resources with the given lifecycle state values.
     */
    sensitiveColumnLifecycleState?: string;
    /**
     * The OCID of the sensitive data model.
     */
    sensitiveDataModelId: string;
    /**
     * A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
     */
    sensitiveTypeIds?: string[];
    /**
     * A filter to return only the sensitive columns that match the specified status.
     */
    statuses?: string[];
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
 * A collection of values returned by getSensitiveDataModelsSensitiveColumns.
 */
export interface GetSensitiveDataModelsSensitiveColumnsResult {
    readonly columnGroup?: string;
    /**
     * The name of the sensitive column.
     */
    readonly columnNames?: string[];
    /**
     * The data type of the sensitive column.
     */
    readonly dataTypes?: string[];
    readonly filters?: outputs.DataSafe.GetSensitiveDataModelsSensitiveColumnsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly isCaseInSensitive?: boolean;
    /**
     * The type of the database object that contains the sensitive column.
     */
    readonly objectTypes?: string[];
    /**
     * The database object that contains the sensitive column.
     */
    readonly objects?: string[];
    readonly parentColumnKeys?: string[];
    /**
     * The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     */
    readonly relationTypes?: string[];
    /**
     * The database schema that contains the sensitive column.
     */
    readonly schemaNames?: string[];
    /**
     * The list of sensitive_column_collection.
     */
    readonly sensitiveColumnCollections: outputs.DataSafe.GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection[];
    readonly sensitiveColumnLifecycleState?: string;
    /**
     * The OCID of the sensitive data model that contains the sensitive column.
     */
    readonly sensitiveDataModelId: string;
    /**
     * The OCID of the sensitive type associated with the sensitive column.
     */
    readonly sensitiveTypeIds?: string[];
    /**
     * The status of the sensitive column. VALID means the column is considered sensitive. INVALID means the column is not considered sensitive. Tracking invalid columns in a sensitive data model helps ensure that an incremental data discovery job does not identify these columns as sensitive again.
     */
    readonly statuses?: string[];
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
    readonly timeUpdatedGreaterThanOrEqualTo?: string;
    readonly timeUpdatedLessThan?: string;
}
/**
 * This data source provides the list of Sensitive Data Models Sensitive Columns in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of sensitive columns present in the specified sensitive data model based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveDataModelsSensitiveColumns = oci.DataSafe.getSensitiveDataModelsSensitiveColumns({
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     columnGroup: sensitiveDataModelsSensitiveColumnColumnGroup,
 *     columnNames: sensitiveDataModelsSensitiveColumnColumnName,
 *     dataTypes: sensitiveDataModelsSensitiveColumnDataType,
 *     isCaseInSensitive: sensitiveDataModelsSensitiveColumnIsCaseInSensitive,
 *     objects: sensitiveDataModelsSensitiveColumnObject,
 *     objectTypes: sensitiveDataModelsSensitiveColumnObjectType,
 *     parentColumnKeys: sensitiveDataModelsSensitiveColumnParentColumnKey,
 *     relationTypes: sensitiveDataModelsSensitiveColumnRelationType,
 *     schemaNames: sensitiveDataModelsSensitiveColumnSchemaName,
 *     sensitiveColumnLifecycleState: sensitiveDataModelsSensitiveColumnSensitiveColumnLifecycleState,
 *     sensitiveTypeIds: testSensitiveType.id,
 *     statuses: sensitiveDataModelsSensitiveColumnStatus,
 *     timeCreatedGreaterThanOrEqualTo: sensitiveDataModelsSensitiveColumnTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: sensitiveDataModelsSensitiveColumnTimeCreatedLessThan,
 *     timeUpdatedGreaterThanOrEqualTo: sensitiveDataModelsSensitiveColumnTimeUpdatedGreaterThanOrEqualTo,
 *     timeUpdatedLessThan: sensitiveDataModelsSensitiveColumnTimeUpdatedLessThan,
 * });
 * ```
 */
export function getSensitiveDataModelsSensitiveColumnsOutput(args: GetSensitiveDataModelsSensitiveColumnsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSensitiveDataModelsSensitiveColumnsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSensitiveDataModelsSensitiveColumns:getSensitiveDataModelsSensitiveColumns", {
        "columnGroup": args.columnGroup,
        "columnNames": args.columnNames,
        "dataTypes": args.dataTypes,
        "filters": args.filters,
        "isCaseInSensitive": args.isCaseInSensitive,
        "objectTypes": args.objectTypes,
        "objects": args.objects,
        "parentColumnKeys": args.parentColumnKeys,
        "relationTypes": args.relationTypes,
        "schemaNames": args.schemaNames,
        "sensitiveColumnLifecycleState": args.sensitiveColumnLifecycleState,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "sensitiveTypeIds": args.sensitiveTypeIds,
        "statuses": args.statuses,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "timeUpdatedGreaterThanOrEqualTo": args.timeUpdatedGreaterThanOrEqualTo,
        "timeUpdatedLessThan": args.timeUpdatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSensitiveDataModelsSensitiveColumns.
 */
export interface GetSensitiveDataModelsSensitiveColumnsOutputArgs {
    /**
     * A filter to return only the sensitive columns that belong to the specified column group.
     */
    columnGroup?: pulumi.Input<string>;
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the resources that match the specified data types.
     */
    dataTypes?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSensitiveDataModelsSensitiveColumnsFilterArgs>[]>;
    /**
     * A boolean flag indicating whether the search should be case-insensitive. The search is case-sensitive by default. Set this parameter to true to do case-insensitive search.
     */
    isCaseInSensitive?: pulumi.Input<boolean>;
    /**
     * A filter to return only items related to a specific object type.
     */
    objectTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the sensitive columns that are children of one of the columns identified by the specified keys.
     */
    parentColumnKeys?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return sensitive columns based on their relationship with their parent columns. If set to NONE, it returns the sensitive columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
     */
    relationTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Filters the sensitive column resources with the given lifecycle state values.
     */
    sensitiveColumnLifecycleState?: pulumi.Input<string>;
    /**
     * The OCID of the sensitive data model.
     */
    sensitiveDataModelId: pulumi.Input<string>;
    /**
     * A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
     */
    sensitiveTypeIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the sensitive columns that match the specified status.
     */
    statuses?: pulumi.Input<pulumi.Input<string>[]>;
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
    /**
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedLessThan?: pulumi.Input<string>;
}
