// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of External Container Databases in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the external container databases in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalContainerDatabases = oci.Database.getExternalContainerDatabases({
 *     compartmentId: compartmentId,
 *     displayName: externalContainerDatabaseDisplayName,
 *     state: externalContainerDatabaseState,
 * });
 * ```
 */
export function getExternalContainerDatabases(args: GetExternalContainerDatabasesArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalContainerDatabasesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getExternalContainerDatabases:getExternalContainerDatabases", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalContainerDatabases.
 */
export interface GetExternalContainerDatabasesArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.Database.GetExternalContainerDatabasesFilter[];
    /**
     * A filter to return only resources that match the specified lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getExternalContainerDatabases.
 */
export interface GetExternalContainerDatabasesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the external database. The name does not have to be unique.
     */
    readonly displayName?: string;
    /**
     * The list of external_container_databases.
     */
    readonly externalContainerDatabases: outputs.Database.GetExternalContainerDatabasesExternalContainerDatabase[];
    readonly filters?: outputs.Database.GetExternalContainerDatabasesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Oracle Cloud Infrastructure external database resource.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of External Container Databases in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the external container databases in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalContainerDatabases = oci.Database.getExternalContainerDatabases({
 *     compartmentId: compartmentId,
 *     displayName: externalContainerDatabaseDisplayName,
 *     state: externalContainerDatabaseState,
 * });
 * ```
 */
export function getExternalContainerDatabasesOutput(args: GetExternalContainerDatabasesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetExternalContainerDatabasesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getExternalContainerDatabases:getExternalContainerDatabases", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalContainerDatabases.
 */
export interface GetExternalContainerDatabasesOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetExternalContainerDatabasesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the specified lifecycle state.
     */
    state?: pulumi.Input<string>;
}
