// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed My Sql Database Outbound Replications in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves information pertaining to outbound replications of a specific MySQL server.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedMySqlDatabaseOutboundReplications = oci.DatabaseManagement.getManagedMySqlDatabaseOutboundReplications({
 *     managedMySqlDatabaseId: testManagedMySqlDatabase.id,
 * });
 * ```
 */
export function getManagedMySqlDatabaseOutboundReplications(args: GetManagedMySqlDatabaseOutboundReplicationsArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedMySqlDatabaseOutboundReplicationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedMySqlDatabaseOutboundReplications:getManagedMySqlDatabaseOutboundReplications", {
        "filters": args.filters,
        "managedMySqlDatabaseId": args.managedMySqlDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedMySqlDatabaseOutboundReplications.
 */
export interface GetManagedMySqlDatabaseOutboundReplicationsArgs {
    filters?: inputs.DatabaseManagement.GetManagedMySqlDatabaseOutboundReplicationsFilter[];
    /**
     * The OCID of the Managed MySQL Database.
     */
    managedMySqlDatabaseId: string;
}

/**
 * A collection of values returned by getManagedMySqlDatabaseOutboundReplications.
 */
export interface GetManagedMySqlDatabaseOutboundReplicationsResult {
    readonly filters?: outputs.DatabaseManagement.GetManagedMySqlDatabaseOutboundReplicationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedMySqlDatabaseId: string;
    /**
     * The list of managed_my_sql_database_outbound_replication_collection.
     */
    readonly managedMySqlDatabaseOutboundReplicationCollections: outputs.DatabaseManagement.GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection[];
}
/**
 * This data source provides the list of Managed My Sql Database Outbound Replications in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves information pertaining to outbound replications of a specific MySQL server.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedMySqlDatabaseOutboundReplications = oci.DatabaseManagement.getManagedMySqlDatabaseOutboundReplications({
 *     managedMySqlDatabaseId: testManagedMySqlDatabase.id,
 * });
 * ```
 */
export function getManagedMySqlDatabaseOutboundReplicationsOutput(args: GetManagedMySqlDatabaseOutboundReplicationsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedMySqlDatabaseOutboundReplicationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedMySqlDatabaseOutboundReplications:getManagedMySqlDatabaseOutboundReplications", {
        "filters": args.filters,
        "managedMySqlDatabaseId": args.managedMySqlDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedMySqlDatabaseOutboundReplications.
 */
export interface GetManagedMySqlDatabaseOutboundReplicationsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedMySqlDatabaseOutboundReplicationsFilterArgs>[]>;
    /**
     * The OCID of the Managed MySQL Database.
     */
    managedMySqlDatabaseId: pulumi.Input<string>;
}
