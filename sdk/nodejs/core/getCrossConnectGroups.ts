// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Cross Connect Groups in Oracle Cloud Infrastructure Core service.
 *
 * Lists the cross-connect groups in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCrossConnectGroups = oci.Core.getCrossConnectGroups({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.cross_connect_group_display_name,
 *     state: _var.cross_connect_group_state,
 * });
 * ```
 */
export function getCrossConnectGroups(args: GetCrossConnectGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetCrossConnectGroupsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getCrossConnectGroups:getCrossConnectGroups", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getCrossConnectGroups.
 */
export interface GetCrossConnectGroupsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetCrossConnectGroupsFilter[];
    /**
     * A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getCrossConnectGroups.
 */
export interface GetCrossConnectGroupsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cross-connect group.
     */
    readonly compartmentId: string;
    /**
     * The list of cross_connect_groups.
     */
    readonly crossConnectGroups: outputs.Core.GetCrossConnectGroupsCrossConnectGroup[];
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetCrossConnectGroupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The cross-connect group's current state.
     */
    readonly state?: string;
}

export function getCrossConnectGroupsOutput(args: GetCrossConnectGroupsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetCrossConnectGroupsResult> {
    return pulumi.output(args).apply(a => getCrossConnectGroups(a, opts))
}

/**
 * A collection of arguments for invoking getCrossConnectGroups.
 */
export interface GetCrossConnectGroupsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetCrossConnectGroupsFilterArgs>[]>;
    /**
     * A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     */
    state?: pulumi.Input<string>;
}
