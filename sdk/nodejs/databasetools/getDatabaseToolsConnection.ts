// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Database Tools Connection resource in Oracle Cloud Infrastructure Database Tools service.
 *
 * Gets details of the specified Database Tools connection.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseToolsConnection = oci.DatabaseTools.getDatabaseToolsConnection({
 *     databaseToolsConnectionId: testDatabaseToolsConnectionOciDatabaseToolsDatabaseToolsConnection.id,
 * });
 * ```
 */
export function getDatabaseToolsConnection(args: GetDatabaseToolsConnectionArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseToolsConnectionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseTools/getDatabaseToolsConnection:getDatabaseToolsConnection", {
        "databaseToolsConnectionId": args.databaseToolsConnectionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseToolsConnection.
 */
export interface GetDatabaseToolsConnectionArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools connection.
     */
    databaseToolsConnectionId: string;
}

/**
 * A collection of values returned by getDatabaseToolsConnection.
 */
export interface GetDatabaseToolsConnectionResult {
    /**
     * The advanced connection properties key-value pair (for example, `oracle.net.ssl_server_dn_match`).
     */
    readonly advancedProperties: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
     */
    readonly compartmentId: string;
    /**
     * The connect descriptor or Easy Connect Naming method used to connect to the database.
     */
    readonly connectionString: string;
    readonly databaseToolsConnectionId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools connection.
     */
    readonly id: string;
    /**
     * The Oracle wallet or Java Keystores containing trusted certificates for authenticating the server's public certificate and the client private key and associated certificates required for client authentication.
     */
    readonly keyStores: outputs.DatabaseTools.GetDatabaseToolsConnectionKeyStore[];
    /**
     * A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Locks associated with this resource.
     */
    readonly locks: outputs.DatabaseTools.GetDatabaseToolsConnectionLock[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
     */
    readonly privateEndpointId: string;
    /**
     * The proxy client information.
     */
    readonly proxyClients: outputs.DatabaseTools.GetDatabaseToolsConnectionProxyClient[];
    /**
     * A related resource
     */
    readonly relatedResources: outputs.DatabaseTools.GetDatabaseToolsConnectionRelatedResource[];
    /**
     * Specifies whether this connection is supported by the Database Tools Runtime.
     */
    readonly runtimeSupport: string;
    /**
     * The current state of the Database Tools connection.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time the Database Tools connection was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    /**
     * The Database Tools connection type.
     */
    readonly type: string;
    /**
     * The JDBC URL used to connect to the Generic JDBC database system.
     */
    readonly url: string;
    /**
     * The database user name.
     */
    readonly userName: string;
    /**
     * The user password.
     */
    readonly userPasswords: outputs.DatabaseTools.GetDatabaseToolsConnectionUserPassword[];
}
/**
 * This data source provides details about a specific Database Tools Connection resource in Oracle Cloud Infrastructure Database Tools service.
 *
 * Gets details of the specified Database Tools connection.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDatabaseToolsConnection = oci.DatabaseTools.getDatabaseToolsConnection({
 *     databaseToolsConnectionId: testDatabaseToolsConnectionOciDatabaseToolsDatabaseToolsConnection.id,
 * });
 * ```
 */
export function getDatabaseToolsConnectionOutput(args: GetDatabaseToolsConnectionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDatabaseToolsConnectionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseTools/getDatabaseToolsConnection:getDatabaseToolsConnection", {
        "databaseToolsConnectionId": args.databaseToolsConnectionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDatabaseToolsConnection.
 */
export interface GetDatabaseToolsConnectionOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools connection.
     */
    databaseToolsConnectionId: pulumi.Input<string>;
}
