// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Database Upgrade History Entries in Oracle Cloud Infrastructure Database service.
 *
 * Gets the upgrade history for a specified database in a bare metal or virtual machine DB system.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseUpgradeHistoryEntries = oci.Database.getDatabaseUpgradeHistoryEntries({
 *     databaseId: testDatabase.id,
 *     state: databaseUpgradeHistoryEntryState,
 *     upgradeAction: databaseUpgradeHistoryEntryUpgradeAction,
 * });
 * ```
 */
export function getDatabaseUpgradeHistoryEntries(args: GetDatabaseUpgradeHistoryEntriesArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseUpgradeHistoryEntriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getDatabaseUpgradeHistoryEntries:getDatabaseUpgradeHistoryEntries", {
        "databaseId": args.databaseId,
        "filters": args.filters,
        "state": args.state,
        "upgradeAction": args.upgradeAction,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseUpgradeHistoryEntries.
 */
export interface GetDatabaseUpgradeHistoryEntriesArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    databaseId: string;
    filters?: inputs.Database.GetDatabaseUpgradeHistoryEntriesFilter[];
    /**
     * A filter to return only upgradeHistoryEntries that match the given lifecycle state exactly.
     */
    state?: string;
    /**
     * A filter to return only upgradeHistoryEntries that match the specified Upgrade Action.
     */
    upgradeAction?: string;
}

/**
 * A collection of values returned by getDatabaseUpgradeHistoryEntries.
 */
export interface GetDatabaseUpgradeHistoryEntriesResult {
    readonly databaseId: string;
    /**
     * The list of database_upgrade_history_entries.
     */
    readonly databaseUpgradeHistoryEntries: outputs.Database.GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry[];
    readonly filters?: outputs.Database.GetDatabaseUpgradeHistoryEntriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
     */
    readonly state?: string;
    readonly upgradeAction?: string;
}
/**
 * This data source provides the list of Database Upgrade History Entries in Oracle Cloud Infrastructure Database service.
 *
 * Gets the upgrade history for a specified database in a bare metal or virtual machine DB system.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseUpgradeHistoryEntries = oci.Database.getDatabaseUpgradeHistoryEntries({
 *     databaseId: testDatabase.id,
 *     state: databaseUpgradeHistoryEntryState,
 *     upgradeAction: databaseUpgradeHistoryEntryUpgradeAction,
 * });
 * ```
 */
export function getDatabaseUpgradeHistoryEntriesOutput(args: GetDatabaseUpgradeHistoryEntriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDatabaseUpgradeHistoryEntriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getDatabaseUpgradeHistoryEntries:getDatabaseUpgradeHistoryEntries", {
        "databaseId": args.databaseId,
        "filters": args.filters,
        "state": args.state,
        "upgradeAction": args.upgradeAction,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseUpgradeHistoryEntries.
 */
export interface GetDatabaseUpgradeHistoryEntriesOutputArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    databaseId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetDatabaseUpgradeHistoryEntriesFilterArgs>[]>;
    /**
     * A filter to return only upgradeHistoryEntries that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
    /**
     * A filter to return only upgradeHistoryEntries that match the specified Upgrade Action.
     */
    upgradeAction?: pulumi.Input<string>;
}
