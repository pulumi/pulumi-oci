// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Db Node Console Connection resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets the specified database node console connection's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNodeConsoleConnection = oci.Database.getDbNodeConsoleConnection({
 *     dbNodeId: testDbNode.id,
 *     id: dbNodeConsoleConnectionId,
 * });
 * ```
 */
export function getDbNodeConsoleConnection(args: GetDbNodeConsoleConnectionArgs, opts?: pulumi.InvokeOptions): Promise<GetDbNodeConsoleConnectionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getDbNodeConsoleConnection:getDbNodeConsoleConnection", {
        "dbNodeId": args.dbNodeId,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNodeConsoleConnection.
 */
export interface GetDbNodeConsoleConnectionArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: string;
    /**
     * The OCID of the console connection.
     */
    id: string;
}

/**
 * A collection of values returned by getDbNodeConsoleConnection.
 */
export interface GetDbNodeConsoleConnectionResult {
    /**
     * The OCID of the compartment to contain the console connection.
     */
    readonly compartmentId: string;
    /**
     * The SSH connection string for the console connection.
     */
    readonly connectionString: string;
    /**
     * The OCID of the database node.
     */
    readonly dbNodeId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The SSH public key fingerprint for the console connection.
     */
    readonly fingerprint: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the console connection.
     */
    readonly id: string;
    /**
     * Information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    readonly publicKey: string;
    /**
     * The SSH public key's fingerprint for the console connection service host.
     */
    readonly serviceHostKeyFingerprint: string;
    /**
     * The current state of the console connection.
     */
    readonly state: string;
}
/**
 * This data source provides details about a specific Db Node Console Connection resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets the specified database node console connection's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNodeConsoleConnection = oci.Database.getDbNodeConsoleConnection({
 *     dbNodeId: testDbNode.id,
 *     id: dbNodeConsoleConnectionId,
 * });
 * ```
 */
export function getDbNodeConsoleConnectionOutput(args: GetDbNodeConsoleConnectionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDbNodeConsoleConnectionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getDbNodeConsoleConnection:getDbNodeConsoleConnection", {
        "dbNodeId": args.dbNodeId,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNodeConsoleConnection.
 */
export interface GetDbNodeConsoleConnectionOutputArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: pulumi.Input<string>;
    /**
     * The OCID of the console connection.
     */
    id: pulumi.Input<string>;
}
