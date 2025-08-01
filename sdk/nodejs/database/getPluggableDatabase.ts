// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Pluggable Database resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified pluggable database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPluggableDatabase = oci.Database.getPluggableDatabase({
 *     pluggableDatabaseId: testPluggableDatabaseOciDatabasePluggableDatabase.id,
 * });
 * ```
 */
export function getPluggableDatabase(args: GetPluggableDatabaseArgs, opts?: pulumi.InvokeOptions): Promise<GetPluggableDatabaseResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getPluggableDatabase:getPluggableDatabase", {
        "pluggableDatabaseId": args.pluggableDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPluggableDatabase.
 */
export interface GetPluggableDatabaseArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    pluggableDatabaseId: string;
}

/**
 * A collection of values returned by getPluggableDatabase.
 */
export interface GetPluggableDatabaseResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Connection strings to connect to an Oracle Pluggable Database.
     */
    readonly connectionStrings: outputs.Database.GetPluggableDatabaseConnectionString[];
    readonly containerDatabaseAdminPassword: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
     */
    readonly containerDatabaseId: string;
    readonly convertToRegularTrigger: number;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pluggable database.
     */
    readonly id: string;
    /**
     * The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
     */
    readonly isRestricted: boolean;
    readonly kmsKeyVersionId: string;
    /**
     * Detailed message for the lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
     */
    readonly openMode: string;
    readonly pdbAdminPassword: string;
    readonly pdbCreationTypeDetails: outputs.Database.GetPluggableDatabasePdbCreationTypeDetail[];
    /**
     * The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
     */
    readonly pdbName: string;
    /**
     * Pluggable Database Node Level Details. Example: [{"nodeName" : "node1", "openMode" : "READ_WRITE"}, {"nodeName" : "node2", "openMode" : "READ_ONLY"}]
     */
    readonly pdbNodeLevelDetails: outputs.Database.GetPluggableDatabasePdbNodeLevelDetail[];
    readonly pluggableDatabaseId: string;
    /**
     * The configuration of the Pluggable Database Management service.
     */
    readonly pluggableDatabaseManagementConfigs: outputs.Database.GetPluggableDatabasePluggableDatabaseManagementConfig[];
    readonly refreshTrigger: number;
    /**
     * Pluggable Database Refreshable Clone Configuration.
     */
    readonly refreshableCloneConfigs: outputs.Database.GetPluggableDatabaseRefreshableCloneConfig[];
    readonly rotateKeyTrigger: number;
    readonly shouldCreatePdbBackup: boolean;
    readonly shouldPdbAdminAccountBeLocked: boolean;
    /**
     * The current state of the pluggable database.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly systemTags: {[key: string]: string};
    readonly tdeWalletPassword: string;
    /**
     * The date and time the pluggable database was created.
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Pluggable Database resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified pluggable database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPluggableDatabase = oci.Database.getPluggableDatabase({
 *     pluggableDatabaseId: testPluggableDatabaseOciDatabasePluggableDatabase.id,
 * });
 * ```
 */
export function getPluggableDatabaseOutput(args: GetPluggableDatabaseOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetPluggableDatabaseResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getPluggableDatabase:getPluggableDatabase", {
        "pluggableDatabaseId": args.pluggableDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPluggableDatabase.
 */
export interface GetPluggableDatabaseOutputArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    pluggableDatabaseId: pulumi.Input<string>;
}
