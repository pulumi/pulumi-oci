// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Target Databases Tables in Oracle Cloud Infrastructure Data Safe service.
 *
 * Returns a list of table metadata objects.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargetDatabasesTables = oci.DataSafe.getTargetDatabasesTables({
 *     targetDatabaseId: testTargetDatabase.id,
 *     schemaNames: targetDatabasesTableSchemaName,
 *     schemaNameContains: targetDatabasesTableSchemaNameContains,
 *     tableNames: testTable.name,
 *     tableNameContains: targetDatabasesTableTableNameContains,
 * });
 * ```
 */
export function getTargetDatabasesTables(args: GetTargetDatabasesTablesArgs, opts?: pulumi.InvokeOptions): Promise<GetTargetDatabasesTablesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getTargetDatabasesTables:getTargetDatabasesTables", {
        "filters": args.filters,
        "schemaNameContains": args.schemaNameContains,
        "schemaNames": args.schemaNames,
        "tableNameContains": args.tableNameContains,
        "tableNames": args.tableNames,
        "targetDatabaseId": args.targetDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTargetDatabasesTables.
 */
export interface GetTargetDatabasesTablesArgs {
    filters?: inputs.DataSafe.GetTargetDatabasesTablesFilter[];
    /**
     * A filter to return only items if schema name contains a specific string.
     */
    schemaNameContains?: string;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: string[];
    /**
     * A filter to return only items if table name contains a specific string.
     */
    tableNameContains?: string;
    /**
     * A filter to return only items related to specific table name.
     */
    tableNames?: string[];
    /**
     * The OCID of the Data Safe target database.
     */
    targetDatabaseId: string;
}

/**
 * A collection of values returned by getTargetDatabasesTables.
 */
export interface GetTargetDatabasesTablesResult {
    readonly filters?: outputs.DataSafe.GetTargetDatabasesTablesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly schemaNameContains?: string;
    /**
     * Name of the schema.
     */
    readonly schemaNames?: string[];
    readonly tableNameContains?: string;
    /**
     * Name of the table.
     */
    readonly tableNames?: string[];
    /**
     * The list of tables.
     */
    readonly tables: outputs.DataSafe.GetTargetDatabasesTablesTable[];
    readonly targetDatabaseId: string;
}
/**
 * This data source provides the list of Target Databases Tables in Oracle Cloud Infrastructure Data Safe service.
 *
 * Returns a list of table metadata objects.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargetDatabasesTables = oci.DataSafe.getTargetDatabasesTables({
 *     targetDatabaseId: testTargetDatabase.id,
 *     schemaNames: targetDatabasesTableSchemaName,
 *     schemaNameContains: targetDatabasesTableSchemaNameContains,
 *     tableNames: testTable.name,
 *     tableNameContains: targetDatabasesTableTableNameContains,
 * });
 * ```
 */
export function getTargetDatabasesTablesOutput(args: GetTargetDatabasesTablesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetTargetDatabasesTablesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getTargetDatabasesTables:getTargetDatabasesTables", {
        "filters": args.filters,
        "schemaNameContains": args.schemaNameContains,
        "schemaNames": args.schemaNames,
        "tableNameContains": args.tableNameContains,
        "tableNames": args.tableNames,
        "targetDatabaseId": args.targetDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTargetDatabasesTables.
 */
export interface GetTargetDatabasesTablesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetTargetDatabasesTablesFilterArgs>[]>;
    /**
     * A filter to return only items if schema name contains a specific string.
     */
    schemaNameContains?: pulumi.Input<string>;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items if table name contains a specific string.
     */
    tableNameContains?: pulumi.Input<string>;
    /**
     * A filter to return only items related to specific table name.
     */
    tableNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the Data Safe target database.
     */
    targetDatabaseId: pulumi.Input<string>;
}
