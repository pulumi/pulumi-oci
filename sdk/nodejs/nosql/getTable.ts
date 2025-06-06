// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Table resource in Oracle Cloud Infrastructure NoSQL Database service.
 *
 * Get table info by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTable = oci.Nosql.getTable({
 *     tableNameOrId: testTableNameOr.id,
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getTable(args: GetTableArgs, opts?: pulumi.InvokeOptions): Promise<GetTableResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Nosql/getTable:getTable", {
        "compartmentId": args.compartmentId,
        "tableNameOrId": args.tableNameOrId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTable.
 */
export interface GetTableArgs {
    /**
     * The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
     */
    compartmentId: string;
    /**
     * A table name within the compartment, or a table OCID.
     */
    tableNameOrId: string;
}

/**
 * A collection of values returned by getTable.
 */
export interface GetTableResult {
    /**
     * Compartment Identifier.
     */
    readonly compartmentId: string;
    /**
     * A DDL statement representing the schema.
     */
    readonly ddlStatement: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Unique identifier that is immutable.
     */
    readonly id: string;
    /**
     * True if this table can be reclaimed after an idle period.
     */
    readonly isAutoReclaimable: boolean;
    /**
     * True if this table is currently a member of a replication set.
     */
    readonly isMultiRegion: boolean;
    /**
     * A message describing the current state in more detail.
     */
    readonly lifecycleDetails: string;
    /**
     * If this table is in a replication set, this value represents the progress of the initialization of the replica's data.  A value of 100 indicates that initialization has completed.
     */
    readonly localReplicaInitializationInPercent: number;
    /**
     * The column name.
     */
    readonly name: string;
    /**
     * An array of Replica listing this table's replicas, if any
     */
    readonly replicas: outputs.Nosql.GetTableReplica[];
    /**
     * The current state of this table's schema. Available states are MUTABLE - The schema can be changed. The table is not eligible for replication. FROZEN - The schema is immutable. The table is eligible for replication.
     */
    readonly schemaState: string;
    /**
     * The table schema information as a JSON object.
     */
    readonly schemas: outputs.Nosql.GetTableSchema[];
    /**
     * The state of a table.
     */
    readonly state: string;
    /**
     * Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `"orcl-cloud"`; and the only key in that namespace is `"free-tier-retained"`. Example: `{"orcl-cloud"": {"free-tier-retained": "true"}}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Throughput and storage limits configuration of a table.
     */
    readonly tableLimits: outputs.Nosql.GetTableTableLimit[];
    readonly tableNameOrId: string;
    /**
     * The time the the table was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
     */
    readonly timeOfExpiration: string;
    /**
     * The time the the table's metadata was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Table resource in Oracle Cloud Infrastructure NoSQL Database service.
 *
 * Get table info by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTable = oci.Nosql.getTable({
 *     tableNameOrId: testTableNameOr.id,
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getTableOutput(args: GetTableOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetTableResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Nosql/getTable:getTable", {
        "compartmentId": args.compartmentId,
        "tableNameOrId": args.tableNameOrId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTable.
 */
export interface GetTableOutputArgs {
    /**
     * The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A table name within the compartment, or a table OCID.
     */
    tableNameOrId: pulumi.Input<string>;
}
