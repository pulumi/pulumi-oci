// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Mysql Backup resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Get information about the specified Backup
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMysqlBackup = oci.Mysql.getMysqlBackup({
 *     backupId: testBackup.id,
 * });
 * ```
 */
export function getMysqlBackup(args: GetMysqlBackupArgs, opts?: pulumi.InvokeOptions): Promise<GetMysqlBackupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Mysql/getMysqlBackup:getMysqlBackup", {
        "backupId": args.backupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMysqlBackup.
 */
export interface GetMysqlBackupArgs {
    /**
     * The OCID of the Backup
     */
    backupId: string;
}

/**
 * A collection of values returned by getMysqlBackup.
 */
export interface GetMysqlBackupResult {
    readonly backupId: string;
    /**
     * The size of the backup in base-2 (IEC) gibibytes. (GiB).
     */
    readonly backupSizeInGbs: number;
    /**
     * The type of backup.
     */
    readonly backupType: string;
    /**
     * The OCID of the compartment the DB System belongs in.
     */
    readonly compartmentId: string;
    /**
     * Indicates how the backup was created: manually, automatic, or by an Operator.
     */
    readonly creationType: string;
    /**
     * DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
     */
    readonly dataStorageSizeInGb: number;
    /**
     * The OCID of the DB System the backup is associated with.
     */
    readonly dbSystemId: string;
    readonly dbSystemSnapshotSummaries: outputs.Mysql.GetMysqlBackupDbSystemSnapshotSummary[];
    /**
     * Snapshot of the DbSystem details at the time of the backup
     */
    readonly dbSystemSnapshots: outputs.Mysql.GetMysqlBackupDbSystemSnapshot[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-supplied description for the backup.
     */
    readonly description: string;
    /**
     * A user-supplied display name for the backup.
     */
    readonly displayName: string;
    /**
     * Encrypt data details.
     */
    readonly encryptDatas: outputs.Mysql.GetMysqlBackupEncryptData[];
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * OCID of the backup itself
     */
    readonly id: string;
    /**
     * The OCID of the immediate source DB system backup from which this DB system backup was copied.
     */
    readonly immediateSourceBackupId: string;
    /**
     * Additional information about the current lifecycleState.
     */
    readonly lifecycleDetails: string;
    /**
     * The MySQL server version of the DB System used for backup.
     */
    readonly mysqlVersion: string;
    /**
     * The OCID of the original source DB system backup from which this DB system backup was copied.
     */
    readonly originalSourceBackupId: string;
    /**
     * Number of days to retain this backup.
     */
    readonly retentionInDays: number;
    /**
     * The shape of the DB System instance used for backup.
     */
    readonly shapeName: string;
    /**
     * Retains the backup to be deleted due to the retention policy in DELETE SCHEDULED state for 7 days before permanently deleting it.
     */
    readonly softDelete: string;
    readonly sourceDetails: outputs.Mysql.GetMysqlBackupSourceDetail[];
    /**
     * The state of the backup.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the DB system backup copy was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    readonly timeCopyCreated: string;
    /**
     * The time the backup record was created.
     */
    readonly timeCreated: string;
    /**
     * The time at which the backup was updated.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Mysql Backup resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Get information about the specified Backup
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMysqlBackup = oci.Mysql.getMysqlBackup({
 *     backupId: testBackup.id,
 * });
 * ```
 */
export function getMysqlBackupOutput(args: GetMysqlBackupOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMysqlBackupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Mysql/getMysqlBackup:getMysqlBackup", {
        "backupId": args.backupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMysqlBackup.
 */
export interface GetMysqlBackupOutputArgs {
    /**
     * The OCID of the Backup
     */
    backupId: pulumi.Input<string>;
}
