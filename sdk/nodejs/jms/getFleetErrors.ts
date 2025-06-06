// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Fleet Errors in Oracle Cloud Infrastructure Jms service.
 *
 * Returns a list of fleet errors that describe all detected errors.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetErrors = oci.Jms.getFleetErrors({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: fleetErrorCompartmentIdInSubtree,
 *     fleetId: testFleet.id,
 *     timeFirstSeenGreaterThanOrEqualTo: fleetErrorTimeFirstSeenGreaterThanOrEqualTo,
 *     timeFirstSeenLessThanOrEqualTo: fleetErrorTimeFirstSeenLessThanOrEqualTo,
 *     timeLastSeenGreaterThanOrEqualTo: fleetErrorTimeLastSeenGreaterThanOrEqualTo,
 *     timeLastSeenLessThanOrEqualTo: fleetErrorTimeLastSeenLessThanOrEqualTo,
 * });
 * ```
 */
export function getFleetErrors(args?: GetFleetErrorsArgs, opts?: pulumi.InvokeOptions): Promise<GetFleetErrorsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getFleetErrors:getFleetErrors", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "timeFirstSeenGreaterThanOrEqualTo": args.timeFirstSeenGreaterThanOrEqualTo,
        "timeFirstSeenLessThanOrEqualTo": args.timeFirstSeenLessThanOrEqualTo,
        "timeLastSeenGreaterThanOrEqualTo": args.timeLastSeenGreaterThanOrEqualTo,
        "timeLastSeenLessThanOrEqualTo": args.timeLastSeenLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetErrors.
 */
export interface GetFleetErrorsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * Flag to determine whether the info should be gathered only in the compartment or in the compartment and its subcompartments.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.Jms.GetFleetErrorsFilter[];
    /**
     * The ID of the Fleet.
     */
    fleetId?: string;
    /**
     * If specified, only errors with a first seen time later than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeFirstSeenGreaterThanOrEqualTo?: string;
    /**
     * If specified, only errors with a first seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeFirstSeenLessThanOrEqualTo?: string;
    /**
     * If specified, only errors with a last seen time later than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeLastSeenGreaterThanOrEqualTo?: string;
    /**
     * If specified, only errors with a last seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeLastSeenLessThanOrEqualTo?: string;
}

/**
 * A collection of values returned by getFleetErrors.
 */
export interface GetFleetErrorsResult {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    readonly compartmentId?: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.Jms.GetFleetErrorsFilter[];
    /**
     * The list of fleet_error_collection.
     */
    readonly fleetErrorCollections: outputs.Jms.GetFleetErrorsFleetErrorCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    readonly fleetId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly timeFirstSeenGreaterThanOrEqualTo?: string;
    readonly timeFirstSeenLessThanOrEqualTo?: string;
    readonly timeLastSeenGreaterThanOrEqualTo?: string;
    readonly timeLastSeenLessThanOrEqualTo?: string;
}
/**
 * This data source provides the list of Fleet Errors in Oracle Cloud Infrastructure Jms service.
 *
 * Returns a list of fleet errors that describe all detected errors.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetErrors = oci.Jms.getFleetErrors({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: fleetErrorCompartmentIdInSubtree,
 *     fleetId: testFleet.id,
 *     timeFirstSeenGreaterThanOrEqualTo: fleetErrorTimeFirstSeenGreaterThanOrEqualTo,
 *     timeFirstSeenLessThanOrEqualTo: fleetErrorTimeFirstSeenLessThanOrEqualTo,
 *     timeLastSeenGreaterThanOrEqualTo: fleetErrorTimeLastSeenGreaterThanOrEqualTo,
 *     timeLastSeenLessThanOrEqualTo: fleetErrorTimeLastSeenLessThanOrEqualTo,
 * });
 * ```
 */
export function getFleetErrorsOutput(args?: GetFleetErrorsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFleetErrorsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Jms/getFleetErrors:getFleetErrors", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "timeFirstSeenGreaterThanOrEqualTo": args.timeFirstSeenGreaterThanOrEqualTo,
        "timeFirstSeenLessThanOrEqualTo": args.timeFirstSeenLessThanOrEqualTo,
        "timeLastSeenGreaterThanOrEqualTo": args.timeLastSeenGreaterThanOrEqualTo,
        "timeLastSeenLessThanOrEqualTo": args.timeLastSeenLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetErrors.
 */
export interface GetFleetErrorsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Flag to determine whether the info should be gathered only in the compartment or in the compartment and its subcompartments.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.Jms.GetFleetErrorsFilterArgs>[]>;
    /**
     * The ID of the Fleet.
     */
    fleetId?: pulumi.Input<string>;
    /**
     * If specified, only errors with a first seen time later than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeFirstSeenGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * If specified, only errors with a first seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeFirstSeenLessThanOrEqualTo?: pulumi.Input<string>;
    /**
     * If specified, only errors with a last seen time later than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeLastSeenGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * If specified, only errors with a last seen time earlier than this parameter will be included in the search (formatted according to RFC3339).
     */
    timeLastSeenLessThanOrEqualTo?: pulumi.Input<string>;
}
