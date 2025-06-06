// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Cross Connect Locations in Oracle Cloud Infrastructure Core service.
 *
 * Lists the available FastConnect locations for cross-connect installation. You need
 * this information so you can specify your desired location when you create a cross-connect.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCrossConnectLocations = oci.Core.getCrossConnectLocations({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getCrossConnectLocations(args: GetCrossConnectLocationsArgs, opts?: pulumi.InvokeOptions): Promise<GetCrossConnectLocationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getCrossConnectLocations:getCrossConnectLocations", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getCrossConnectLocations.
 */
export interface GetCrossConnectLocationsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.Core.GetCrossConnectLocationsFilter[];
}

/**
 * A collection of values returned by getCrossConnectLocations.
 */
export interface GetCrossConnectLocationsResult {
    readonly compartmentId: string;
    /**
     * The list of cross_connect_locations.
     */
    readonly crossConnectLocations: outputs.Core.GetCrossConnectLocationsCrossConnectLocation[];
    readonly filters?: outputs.Core.GetCrossConnectLocationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Cross Connect Locations in Oracle Cloud Infrastructure Core service.
 *
 * Lists the available FastConnect locations for cross-connect installation. You need
 * this information so you can specify your desired location when you create a cross-connect.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCrossConnectLocations = oci.Core.getCrossConnectLocations({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getCrossConnectLocationsOutput(args: GetCrossConnectLocationsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetCrossConnectLocationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getCrossConnectLocations:getCrossConnectLocations", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getCrossConnectLocations.
 */
export interface GetCrossConnectLocationsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetCrossConnectLocationsFilterArgs>[]>;
}
