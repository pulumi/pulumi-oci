// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Databases in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the databases in the specified Database Home.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabases = oci.Database.getDatabases({
 *     compartmentId: compartmentId,
 *     dbHomeId: testDbHome.id,
 *     dbName: databaseDbName,
 *     state: databaseState,
 *     systemId: testSystem.id,
 * });
 * ```
 */
export function getDatabases(args: GetDatabasesArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabasesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getDatabases:getDatabases", {
        "compartmentId": args.compartmentId,
        "dbHomeId": args.dbHomeId,
        "dbName": args.dbName,
        "filters": args.filters,
        "state": args.state,
        "systemId": args.systemId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabases.
 */
export interface GetDatabasesArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). *Note: Either `dbHomeId` or `systemId` is required to make the LIST API call.
     */
    dbHomeId?: string;
    /**
     * A filter to return only resources that match the entire database name given. The match is not case sensitive.
     */
    dbName?: string;
    filters?: inputs.Database.GetDatabasesFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata DB system that you want to filter the database results by. Applies only to Exadata DB systems.
     */
    systemId?: string;
}

/**
 * A collection of values returned by getDatabases.
 */
export interface GetDatabasesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The list of databases.
     */
    readonly databases: outputs.Database.GetDatabasesDatabase[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     */
    readonly dbHomeId?: string;
    /**
     * The database name.
     */
    readonly dbName?: string;
    readonly filters?: outputs.Database.GetDatabasesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the database.
     */
    readonly state?: string;
    readonly systemId?: string;
}
/**
 * This data source provides the list of Databases in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the databases in the specified Database Home.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabases = oci.Database.getDatabases({
 *     compartmentId: compartmentId,
 *     dbHomeId: testDbHome.id,
 *     dbName: databaseDbName,
 *     state: databaseState,
 *     systemId: testSystem.id,
 * });
 * ```
 */
export function getDatabasesOutput(args: GetDatabasesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDatabasesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getDatabases:getDatabases", {
        "compartmentId": args.compartmentId,
        "dbHomeId": args.dbHomeId,
        "dbName": args.dbName,
        "filters": args.filters,
        "state": args.state,
        "systemId": args.systemId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabases.
 */
export interface GetDatabasesOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). *Note: Either `dbHomeId` or `systemId` is required to make the LIST API call.
     */
    dbHomeId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire database name given. The match is not case sensitive.
     */
    dbName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetDatabasesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata DB system that you want to filter the database results by. Applies only to Exadata DB systems.
     */
    systemId?: pulumi.Input<string>;
}
