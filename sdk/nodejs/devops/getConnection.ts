// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Connection resource in Oracle Cloud Infrastructure Devops service.
 *
 * Retrieves a connection by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConnection = oci.DevOps.getConnection({
 *     connectionId: oci_devops_connection.test_connection.id,
 * });
 * ```
 */
export function getConnection(args: GetConnectionArgs, opts?: pulumi.InvokeOptions): Promise<GetConnectionResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DevOps/getConnection:getConnection", {
        "connectionId": args.connectionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getConnection.
 */
export interface GetConnectionArgs {
    /**
     * Unique connection identifier.
     */
    connectionId: string;
}

/**
 * A collection of values returned by getConnection.
 */
export interface GetConnectionResult {
    /**
     * The OCID of personal access token saved in secret store.
     */
    readonly accessToken: string;
    /**
     * OCID of personal Bitbucket Cloud AppPassword saved in secret store
     */
    readonly appPassword: string;
    /**
     * The Base URL of the hosted BitbucketServer.
     */
    readonly baseUrl: string;
    /**
     * The OCID of the compartment containing the connection.
     */
    readonly compartmentId: string;
    readonly connectionId: string;
    /**
     * The type of connection.
     */
    readonly connectionType: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Optional description about the connection.
     */
    readonly description: string;
    /**
     * Connection display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id: string;
    /**
     * The OCID of the DevOps project.
     */
    readonly projectId: string;
    /**
     * The current state of the connection.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    readonly timeUpdated: string;
    /**
     * TLS configuration used by build service to verify TLS connection.
     */
    readonly tlsVerifyConfigs: outputs.DevOps.GetConnectionTlsVerifyConfig[];
    /**
     * Public Bitbucket Cloud Username in plain text
     */
    readonly username: string;
}

export function getConnectionOutput(args: GetConnectionOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetConnectionResult> {
    return pulumi.output(args).apply(a => getConnection(a, opts))
}

/**
 * A collection of arguments for invoking getConnection.
 */
export interface GetConnectionOutputArgs {
    /**
     * Unique connection identifier.
     */
    connectionId: pulumi.Input<string>;
}