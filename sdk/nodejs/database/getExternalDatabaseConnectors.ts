// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of External Database Connectors in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the external database connectors in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDatabaseConnectors = oci.Database.getExternalDatabaseConnectors({
 *     compartmentId: compartmentId,
 *     externalDatabaseId: testDatabase.id,
 *     displayName: externalDatabaseConnectorDisplayName,
 *     state: externalDatabaseConnectorState,
 * });
 * ```
 */
export function getExternalDatabaseConnectors(args: GetExternalDatabaseConnectorsArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalDatabaseConnectorsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getExternalDatabaseConnectors:getExternalDatabaseConnectors", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "externalDatabaseId": args.externalDatabaseId,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalDatabaseConnectors.
 */
export interface GetExternalDatabaseConnectorsArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database whose connectors will be listed.
     */
    externalDatabaseId: string;
    filters?: inputs.Database.GetExternalDatabaseConnectorsFilter[];
    /**
     * A filter to return only resources that match the specified lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getExternalDatabaseConnectors.
 */
export interface GetExternalDatabaseConnectorsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
     */
    readonly displayName?: string;
    /**
     * The list of external_database_connectors.
     */
    readonly externalDatabaseConnectors: outputs.Database.GetExternalDatabaseConnectorsExternalDatabaseConnector[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
     */
    readonly externalDatabaseId: string;
    readonly filters?: outputs.Database.GetExternalDatabaseConnectorsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current lifecycle state of the external database connector resource.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of External Database Connectors in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the external database connectors in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDatabaseConnectors = oci.Database.getExternalDatabaseConnectors({
 *     compartmentId: compartmentId,
 *     externalDatabaseId: testDatabase.id,
 *     displayName: externalDatabaseConnectorDisplayName,
 *     state: externalDatabaseConnectorState,
 * });
 * ```
 */
export function getExternalDatabaseConnectorsOutput(args: GetExternalDatabaseConnectorsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetExternalDatabaseConnectorsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getExternalDatabaseConnectors:getExternalDatabaseConnectors", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "externalDatabaseId": args.externalDatabaseId,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalDatabaseConnectors.
 */
export interface GetExternalDatabaseConnectorsOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database whose connectors will be listed.
     */
    externalDatabaseId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetExternalDatabaseConnectorsFilterArgs>[]>;
    /**
     * A filter to return only resources that match the specified lifecycle state.
     */
    state?: pulumi.Input<string>;
}
