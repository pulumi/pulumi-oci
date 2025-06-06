// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Instance Console Connections in Oracle Cloud Infrastructure Core service.
 *
 * Lists the console connections for the specified compartment or instance.
 *
 * For more information about instance console connections, see [Troubleshooting Instances Using Instance Console Connections](https://docs.cloud.oracle.com/iaas/Content/Compute/References/serialconsole.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstanceConsoleConnections = oci.Core.getInstanceConsoleConnections({
 *     compartmentId: compartmentId,
 *     instanceId: testInstance.id,
 * });
 * ```
 */
export function getInstanceConsoleConnections(args: GetInstanceConsoleConnectionsArgs, opts?: pulumi.InvokeOptions): Promise<GetInstanceConsoleConnectionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getInstanceConsoleConnections:getInstanceConsoleConnections", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "instanceId": args.instanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstanceConsoleConnections.
 */
export interface GetInstanceConsoleConnectionsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.Core.GetInstanceConsoleConnectionsFilter[];
    /**
     * The OCID of the instance.
     */
    instanceId?: string;
}

/**
 * A collection of values returned by getInstanceConsoleConnections.
 */
export interface GetInstanceConsoleConnectionsResult {
    /**
     * The OCID of the compartment to contain the console connection.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Core.GetInstanceConsoleConnectionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of instance_console_connections.
     */
    readonly instanceConsoleConnections: outputs.Core.GetInstanceConsoleConnectionsInstanceConsoleConnection[];
    /**
     * The OCID of the instance the console connection connects to.
     */
    readonly instanceId?: string;
}
/**
 * This data source provides the list of Instance Console Connections in Oracle Cloud Infrastructure Core service.
 *
 * Lists the console connections for the specified compartment or instance.
 *
 * For more information about instance console connections, see [Troubleshooting Instances Using Instance Console Connections](https://docs.cloud.oracle.com/iaas/Content/Compute/References/serialconsole.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstanceConsoleConnections = oci.Core.getInstanceConsoleConnections({
 *     compartmentId: compartmentId,
 *     instanceId: testInstance.id,
 * });
 * ```
 */
export function getInstanceConsoleConnectionsOutput(args: GetInstanceConsoleConnectionsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInstanceConsoleConnectionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getInstanceConsoleConnections:getInstanceConsoleConnections", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "instanceId": args.instanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstanceConsoleConnections.
 */
export interface GetInstanceConsoleConnectionsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetInstanceConsoleConnectionsFilterArgs>[]>;
    /**
     * The OCID of the instance.
     */
    instanceId?: pulumi.Input<string>;
}
