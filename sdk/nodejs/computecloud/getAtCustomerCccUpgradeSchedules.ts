// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Ccc Upgrade Schedules in Oracle Cloud Infrastructure Compute Cloud At Customer service.
 *
 * Returns a list of Compute Cloud@Customer upgrade schedules.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCccUpgradeSchedules = oci.ComputeCloud.getAtCustomerCccUpgradeSchedules({
 *     accessLevel: _var.ccc_upgrade_schedule_access_level,
 *     cccUpgradeScheduleId: oci_compute_cloud_at_customer_ccc_upgrade_schedule.test_ccc_upgrade_schedule.id,
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.ccc_upgrade_schedule_compartment_id_in_subtree,
 *     displayName: _var.ccc_upgrade_schedule_display_name,
 *     displayNameContains: _var.ccc_upgrade_schedule_display_name_contains,
 *     state: _var.ccc_upgrade_schedule_state,
 * });
 * ```
 */
export function getAtCustomerCccUpgradeSchedules(args?: GetAtCustomerCccUpgradeSchedulesArgs, opts?: pulumi.InvokeOptions): Promise<GetAtCustomerCccUpgradeSchedulesResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ComputeCloud/getAtCustomerCccUpgradeSchedules:getAtCustomerCccUpgradeSchedules", {
        "accessLevel": args.accessLevel,
        "cccUpgradeScheduleId": args.cccUpgradeScheduleId,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "displayNameContains": args.displayNameContains,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAtCustomerCccUpgradeSchedules.
 */
export interface GetAtCustomerCccUpgradeSchedulesArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * Compute Cloud@Customer upgrade schedule [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    cccUpgradeScheduleId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    /**
     * A filter to return only resources whose display name contains the substring.
     */
    displayNameContains?: string;
    filters?: inputs.ComputeCloud.GetAtCustomerCccUpgradeSchedulesFilter[];
    /**
     * A filter to return resources only when their lifecycleState matches the given lifecycleState.
     */
    state?: string;
}

/**
 * A collection of values returned by getAtCustomerCccUpgradeSchedules.
 */
export interface GetAtCustomerCccUpgradeSchedulesResult {
    readonly accessLevel?: string;
    /**
     * The list of ccc_upgrade_schedule_collection.
     */
    readonly cccUpgradeScheduleCollections: outputs.ComputeCloud.GetAtCustomerCccUpgradeSchedulesCccUpgradeScheduleCollection[];
    readonly cccUpgradeScheduleId?: string;
    /**
     * Compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Compute Cloud@Customer upgrade schedule.
     */
    readonly compartmentId?: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * Compute Cloud@Customer upgrade schedule display name. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly displayNameContains?: string;
    readonly filters?: outputs.ComputeCloud.GetAtCustomerCccUpgradeSchedulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Lifecycle state of the resource.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Ccc Upgrade Schedules in Oracle Cloud Infrastructure Compute Cloud At Customer service.
 *
 * Returns a list of Compute Cloud@Customer upgrade schedules.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCccUpgradeSchedules = oci.ComputeCloud.getAtCustomerCccUpgradeSchedules({
 *     accessLevel: _var.ccc_upgrade_schedule_access_level,
 *     cccUpgradeScheduleId: oci_compute_cloud_at_customer_ccc_upgrade_schedule.test_ccc_upgrade_schedule.id,
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.ccc_upgrade_schedule_compartment_id_in_subtree,
 *     displayName: _var.ccc_upgrade_schedule_display_name,
 *     displayNameContains: _var.ccc_upgrade_schedule_display_name_contains,
 *     state: _var.ccc_upgrade_schedule_state,
 * });
 * ```
 */
export function getAtCustomerCccUpgradeSchedulesOutput(args?: GetAtCustomerCccUpgradeSchedulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAtCustomerCccUpgradeSchedulesResult> {
    return pulumi.output(args).apply((a: any) => getAtCustomerCccUpgradeSchedules(a, opts))
}

/**
 * A collection of arguments for invoking getAtCustomerCccUpgradeSchedules.
 */
export interface GetAtCustomerCccUpgradeSchedulesOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * Compute Cloud@Customer upgrade schedule [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    cccUpgradeScheduleId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A filter to return only resources whose display name contains the substring.
     */
    displayNameContains?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ComputeCloud.GetAtCustomerCccUpgradeSchedulesFilterArgs>[]>;
    /**
     * A filter to return resources only when their lifecycleState matches the given lifecycleState.
     */
    state?: pulumi.Input<string>;
}