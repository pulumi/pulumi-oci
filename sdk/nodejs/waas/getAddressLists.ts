// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Address Lists in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Gets a list of address lists that can be used in a WAAS policy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddressLists = oci.Waas.getAddressLists({
 *     compartmentId: _var.compartment_id,
 *     ids: _var.address_list_ids,
 *     names: _var.address_list_names,
 *     states: _var.address_list_states,
 *     timeCreatedGreaterThanOrEqualTo: _var.address_list_time_created_greater_than_or_equal_to,
 *     timeCreatedLessThan: _var.address_list_time_created_less_than,
 * });
 * ```
 */
export function getAddressLists(args: GetAddressListsArgs, opts?: pulumi.InvokeOptions): Promise<GetAddressListsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Waas/getAddressLists:getAddressLists", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "ids": args.ids,
        "names": args.names,
        "states": args.states,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddressLists.
 */
export interface GetAddressListsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     */
    compartmentId: string;
    filters?: inputs.Waas.GetAddressListsFilter[];
    /**
     * Filter address lists using a list of address lists OCIDs.
     */
    ids?: string[];
    /**
     * Filter address lists using a list of names.
     */
    names?: string[];
    /**
     * Filter address lists using a list of lifecycle states.
     */
    states?: string[];
    /**
     * A filter that matches address lists created on or after the specified date-time.
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * A filter that matches address lists created before the specified date-time.
     */
    timeCreatedLessThan?: string;
}

/**
 * A collection of values returned by getAddressLists.
 */
export interface GetAddressListsResult {
    /**
     * The list of address_lists.
     */
    readonly addressLists: outputs.Waas.GetAddressListsAddressList[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list's compartment.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Waas.GetAddressListsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly ids?: string[];
    readonly names?: string[];
    readonly states?: string[];
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
}

export function getAddressListsOutput(args: GetAddressListsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAddressListsResult> {
    return pulumi.output(args).apply(a => getAddressLists(a, opts))
}

/**
 * A collection of arguments for invoking getAddressLists.
 */
export interface GetAddressListsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Waas.GetAddressListsFilterArgs>[]>;
    /**
     * Filter address lists using a list of address lists OCIDs.
     */
    ids?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Filter address lists using a list of names.
     */
    names?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Filter address lists using a list of lifecycle states.
     */
    states?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter that matches address lists created on or after the specified date-time.
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * A filter that matches address lists created before the specified date-time.
     */
    timeCreatedLessThan?: pulumi.Input<string>;
}