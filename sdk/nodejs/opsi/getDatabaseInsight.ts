// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Database Insight resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets details of a database insight.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseInsight = oci.Opsi.getDatabaseInsight({
 *     databaseInsightId: oci_opsi_database_insight.test_database_insight.id,
 * });
 * ```
 */
export function getDatabaseInsight(args: GetDatabaseInsightArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseInsightResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opsi/getDatabaseInsight:getDatabaseInsight", {
        "databaseInsightId": args.databaseInsightId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseInsight.
 */
export interface GetDatabaseInsightArgs {
    /**
     * Unique database insight identifier
     */
    databaseInsightId: string;
}

/**
 * A collection of values returned by getDatabaseInsight.
 */
export interface GetDatabaseInsightResult {
    /**
     * Compartment identifier of the database
     */
    readonly compartmentId: string;
    /**
     * User credential details to connect to the database. This is supplied via the External Database Service.
     */
    readonly connectionCredentialDetails: outputs.Opsi.GetDatabaseInsightConnectionCredentialDetail[];
    /**
     * Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    readonly connectionDetails: outputs.Opsi.GetDatabaseInsightConnectionDetail[];
    /**
     * User credential details to connect to the database.
     */
    readonly credentialDetails: outputs.Opsi.GetDatabaseInsightCredentialDetail[];
    /**
     * A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
     */
    readonly databaseConnectionStatusDetails: string;
    /**
     * Display name of database
     */
    readonly databaseDisplayName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     */
    readonly databaseId: string;
    readonly databaseInsightId: string;
    /**
     * Name of database
     */
    readonly databaseName: string;
    /**
     * Oracle Cloud Infrastructure database resource type
     */
    readonly databaseResourceType: string;
    /**
     * Operations Insights internal representation of the database type.
     */
    readonly databaseType: string;
    /**
     * The version of the database.
     */
    readonly databaseVersion: string;
    readonly dbmPrivateEndpointId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    readonly deploymentType: string;
    /**
     * OPSI Enterprise Manager Bridge OCID
     */
    readonly enterpriseManagerBridgeId: string;
    /**
     * Enterprise Manager Entity Display Name
     */
    readonly enterpriseManagerEntityDisplayName: string;
    /**
     * Enterprise Manager Entity Unique Identifier
     */
    readonly enterpriseManagerEntityIdentifier: string;
    /**
     * Enterprise Manager Entity Name
     */
    readonly enterpriseManagerEntityName: string;
    /**
     * Enterprise Manager Entity Type
     */
    readonly enterpriseManagerEntityType: string;
    /**
     * Enterprise Manager Unqiue Identifier
     */
    readonly enterpriseManagerIdentifier: string;
    /**
     * Source of the database entity.
     */
    readonly entitySource: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     */
    readonly exadataInsightId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Database insight identifier
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     */
    readonly opsiPrivateEndpointId: string;
    /**
     * Processor count. This is the OCPU count for Autonomous Database and CPU core count for other database types.
     */
    readonly processorCount: number;
    /**
     * Database service name used for connection requests.
     */
    readonly serviceName: string;
    /**
     * The current state of the database.
     */
    readonly state: string;
    /**
     * Indicates the status of a database insight in Operations Insights
     */
    readonly status: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the the database insight was first enabled. An RFC3339 formatted datetime string
     */
    readonly timeCreated: string;
    /**
     * The time the database insight was updated. An RFC3339 formatted datetime string
     */
    readonly timeUpdated: string;
}

export function getDatabaseInsightOutput(args: GetDatabaseInsightOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDatabaseInsightResult> {
    return pulumi.output(args).apply(a => getDatabaseInsight(a, opts))
}

/**
 * A collection of arguments for invoking getDatabaseInsight.
 */
export interface GetDatabaseInsightOutputArgs {
    /**
     * Unique database insight identifier
     */
    databaseInsightId: pulumi.Input<string>;
}