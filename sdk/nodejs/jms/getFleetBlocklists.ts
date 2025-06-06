// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Fleet Blocklists in Oracle Cloud Infrastructure Jms service.
 *
 * Returns a list of blocklist entities contained by a fleet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetBlocklists = oci.Jms.getFleetBlocklists({
 *     fleetId: testFleet.id,
 *     managedInstanceId: fleetBlocklistManagedInstanceId,
 *     operation: fleetBlocklistOperation,
 * });
 * ```
 */
export function getFleetBlocklists(args: GetFleetBlocklistsArgs, opts?: pulumi.InvokeOptions): Promise<GetFleetBlocklistsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getFleetBlocklists:getFleetBlocklists", {
        "filters": args.filters,
        "fleetId": args.fleetId,
        "managedInstanceId": args.managedInstanceId,
        "operation": args.operation,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetBlocklists.
 */
export interface GetFleetBlocklistsArgs {
    filters?: inputs.Jms.GetFleetBlocklistsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: string;
    /**
     * The Fleet-unique identifier of the related managed instance.
     */
    managedInstanceId?: string;
    /**
     * The operation type.
     */
    operation?: string;
}

/**
 * A collection of values returned by getFleetBlocklists.
 */
export interface GetFleetBlocklistsResult {
    readonly filters?: outputs.Jms.GetFleetBlocklistsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
     */
    readonly fleetId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The blocklist
     */
    readonly items: outputs.Jms.GetFleetBlocklistsItem[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance.
     */
    readonly managedInstanceId?: string;
    /**
     * The operation type
     */
    readonly operation?: string;
}
/**
 * This data source provides the list of Fleet Blocklists in Oracle Cloud Infrastructure Jms service.
 *
 * Returns a list of blocklist entities contained by a fleet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetBlocklists = oci.Jms.getFleetBlocklists({
 *     fleetId: testFleet.id,
 *     managedInstanceId: fleetBlocklistManagedInstanceId,
 *     operation: fleetBlocklistOperation,
 * });
 * ```
 */
export function getFleetBlocklistsOutput(args: GetFleetBlocklistsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFleetBlocklistsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Jms/getFleetBlocklists:getFleetBlocklists", {
        "filters": args.filters,
        "fleetId": args.fleetId,
        "managedInstanceId": args.managedInstanceId,
        "operation": args.operation,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetBlocklists.
 */
export interface GetFleetBlocklistsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Jms.GetFleetBlocklistsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: pulumi.Input<string>;
    /**
     * The Fleet-unique identifier of the related managed instance.
     */
    managedInstanceId?: pulumi.Input<string>;
    /**
     * The operation type.
     */
    operation?: pulumi.Input<string>;
}
