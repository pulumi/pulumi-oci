// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Fleet resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Get the details of a fleet in Fleet Application Management.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleet = oci.FleetAppsManagement.getFleet({
 *     fleetId: testFleetOciFleetAppsManagementFleet.id,
 * });
 * ```
 */
export function getFleet(args: GetFleetArgs, opts?: pulumi.InvokeOptions): Promise<GetFleetResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FleetAppsManagement/getFleet:getFleet", {
        "fleetId": args.fleetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleet.
 */
export interface GetFleetArgs {
    /**
     * Unique Fleet identifier.
     */
    fleetId: string;
}

/**
 * A collection of values returned by getFleet.
 */
export interface GetFleetResult {
    /**
     * Compartment Identifier[OCID].
     */
    readonly compartmentId: string;
    /**
     * Credentials associated with the Fleet.
     */
    readonly credentials: outputs.FleetAppsManagement.GetFleetCredential[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * Fleet Type
     */
    readonly details: outputs.FleetAppsManagement.GetFleetDetail[];
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName: string;
    /**
     * Environment Type associated with the Fleet. Applicable for ENVIRONMENT fleet types.
     */
    readonly environmentType: string;
    readonly fleetId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the resource.
     */
    readonly id: string;
    /**
     * A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
     */
    readonly isTargetAutoConfirm: boolean;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Notification Preferences associated with the Fleet.
     */
    readonly notificationPreferences: outputs.FleetAppsManagement.GetFleetNotificationPreference[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
     */
    readonly parentFleetId: string;
    /**
     * Products associated with the Fleet.
     */
    readonly products: string[];
    /**
     * Properties associated with the Fleet.
     */
    readonly properties: outputs.FleetAppsManagement.GetFleetProperty[];
    /**
     * Associated region
     */
    readonly resourceRegion: string;
    /**
     * Resource Selection Type
     */
    readonly resourceSelections: outputs.FleetAppsManagement.GetFleetResourceSelection[];
    /**
     * Resources associated with the Fleet if resourceSelectionType is MANUAL.
     */
    readonly resources: outputs.FleetAppsManagement.GetFleetResource[];
    /**
     * The lifecycle state of the Fleet.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Fleet resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Get the details of a fleet in Fleet Application Management.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleet = oci.FleetAppsManagement.getFleet({
 *     fleetId: testFleetOciFleetAppsManagementFleet.id,
 * });
 * ```
 */
export function getFleetOutput(args: GetFleetOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFleetResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FleetAppsManagement/getFleet:getFleet", {
        "fleetId": args.fleetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleet.
 */
export interface GetFleetOutputArgs {
    /**
     * Unique Fleet identifier.
     */
    fleetId: pulumi.Input<string>;
}
