// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed My Sql Database Inbound Replications in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves information about the inbound replications of a specific MySQL server.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedMySqlDatabaseInboundReplications = oci.DatabaseManagement.getManagedMySqlDatabaseInboundReplications({
 *     managedMySqlDatabaseId: testManagedMySqlDatabase.id,
 * });
 * ```
 */
export function getManagedMySqlDatabaseInboundReplications(args: GetManagedMySqlDatabaseInboundReplicationsArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedMySqlDatabaseInboundReplicationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedMySqlDatabaseInboundReplications:getManagedMySqlDatabaseInboundReplications", {
        "filters": args.filters,
        "managedMySqlDatabaseId": args.managedMySqlDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedMySqlDatabaseInboundReplications.
 */
export interface GetManagedMySqlDatabaseInboundReplicationsArgs {
    filters?: inputs.DatabaseManagement.GetManagedMySqlDatabaseInboundReplicationsFilter[];
    /**
     * The OCID of the Managed MySQL Database.
     */
    managedMySqlDatabaseId: string;
}

/**
 * A collection of values returned by getManagedMySqlDatabaseInboundReplications.
 */
export interface GetManagedMySqlDatabaseInboundReplicationsResult {
    readonly filters?: outputs.DatabaseManagement.GetManagedMySqlDatabaseInboundReplicationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedMySqlDatabaseId: string;
    /**
     * The list of managed_my_sql_database_inbound_replication_collection.
     */
    readonly managedMySqlDatabaseInboundReplicationCollections: outputs.DatabaseManagement.GetManagedMySqlDatabaseInboundReplicationsManagedMySqlDatabaseInboundReplicationCollection[];
}
/**
 * This data source provides the list of Managed My Sql Database Inbound Replications in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves information about the inbound replications of a specific MySQL server.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedMySqlDatabaseInboundReplications = oci.DatabaseManagement.getManagedMySqlDatabaseInboundReplications({
 *     managedMySqlDatabaseId: testManagedMySqlDatabase.id,
 * });
 * ```
 */
export function getManagedMySqlDatabaseInboundReplicationsOutput(args: GetManagedMySqlDatabaseInboundReplicationsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedMySqlDatabaseInboundReplicationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedMySqlDatabaseInboundReplications:getManagedMySqlDatabaseInboundReplications", {
        "filters": args.filters,
        "managedMySqlDatabaseId": args.managedMySqlDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedMySqlDatabaseInboundReplications.
 */
export interface GetManagedMySqlDatabaseInboundReplicationsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedMySqlDatabaseInboundReplicationsFilterArgs>[]>;
    /**
     * The OCID of the Managed MySQL Database.
     */
    managedMySqlDatabaseId: pulumi.Input<string>;
}
