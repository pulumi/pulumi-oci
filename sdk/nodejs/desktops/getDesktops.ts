// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Desktops in Oracle Cloud Infrastructure Desktops service.
 *
 * Returns a list of desktops filtered by the specified parameters. You can limit the results to an availability domain, desktop name, desktop OCID, desktop state, pool OCID, or compartment OCID. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDesktops = oci.Desktops.getDesktops({
 *     compartmentId: compartmentId,
 *     availabilityDomain: desktopAvailabilityDomain,
 *     desktopPoolId: testDesktopPool.id,
 *     displayName: desktopDisplayName,
 *     id: desktopId,
 *     state: desktopState,
 * });
 * ```
 */
export function getDesktops(args: GetDesktopsArgs, opts?: pulumi.InvokeOptions): Promise<GetDesktopsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Desktops/getDesktops:getDesktops", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "desktopPoolId": args.desktopPoolId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDesktops.
 */
export interface GetDesktopsArgs {
    /**
     * The name of the availability domain.
     */
    availabilityDomain?: string;
    /**
     * The OCID of the compartment of the desktop pool.
     */
    compartmentId: string;
    /**
     * The OCID of the desktop pool.
     */
    desktopPoolId?: string;
    /**
     * A filter to return only results with the given displayName.
     */
    displayName?: string;
    filters?: inputs.Desktops.GetDesktopsFilter[];
    /**
     * A filter to return only results with the given OCID.
     */
    id?: string;
    /**
     * A filter to return only results with the given lifecycleState.
     */
    state?: string;
}

/**
 * A collection of values returned by getDesktops.
 */
export interface GetDesktopsResult {
    readonly availabilityDomain?: string;
    readonly compartmentId: string;
    /**
     * The list of desktop_collection.
     */
    readonly desktopCollections: outputs.Desktops.GetDesktopsDesktopCollection[];
    readonly desktopPoolId?: string;
    /**
     * A user friendly display name. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Desktops.GetDesktopsFilter[];
    /**
     * The OCID of the desktop.
     */
    readonly id?: string;
    /**
     * The state of the desktop.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Desktops in Oracle Cloud Infrastructure Desktops service.
 *
 * Returns a list of desktops filtered by the specified parameters. You can limit the results to an availability domain, desktop name, desktop OCID, desktop state, pool OCID, or compartment OCID. You can limit the number of results returned, sort the results by time or name, and sort in ascending or descending order.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDesktops = oci.Desktops.getDesktops({
 *     compartmentId: compartmentId,
 *     availabilityDomain: desktopAvailabilityDomain,
 *     desktopPoolId: testDesktopPool.id,
 *     displayName: desktopDisplayName,
 *     id: desktopId,
 *     state: desktopState,
 * });
 * ```
 */
export function getDesktopsOutput(args: GetDesktopsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDesktopsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Desktops/getDesktops:getDesktops", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "desktopPoolId": args.desktopPoolId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDesktops.
 */
export interface GetDesktopsOutputArgs {
    /**
     * The name of the availability domain.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The OCID of the compartment of the desktop pool.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The OCID of the desktop pool.
     */
    desktopPoolId?: pulumi.Input<string>;
    /**
     * A filter to return only results with the given displayName.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Desktops.GetDesktopsFilterArgs>[]>;
    /**
     * A filter to return only results with the given OCID.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only results with the given lifecycleState.
     */
    state?: pulumi.Input<string>;
}
