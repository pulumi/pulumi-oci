// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Dr Protection Group resource in Oracle Cloud Infrastructure Disaster Recovery service.
 *
 * Get the DR Protection Group identified by *drProtectionGroupId*.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrProtectionGroup = oci.DisasterRecovery.getDrProtectionGroup({
 *     drProtectionGroupId: oci_disaster_recovery_dr_protection_group.test_dr_protection_group.id,
 * });
 * ```
 */
export function getDrProtectionGroup(args: GetDrProtectionGroupArgs, opts?: pulumi.InvokeOptions): Promise<GetDrProtectionGroupResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DisasterRecovery/getDrProtectionGroup:getDrProtectionGroup", {
        "drProtectionGroupId": args.drProtectionGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDrProtectionGroup.
 */
export interface GetDrProtectionGroupArgs {
    /**
     * The OCID of the DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     */
    drProtectionGroupId: string;
}

/**
 * A collection of values returned by getDrProtectionGroup.
 */
export interface GetDrProtectionGroupResult {
    readonly associations: outputs.DisasterRecovery.GetDrProtectionGroupAssociation[];
    /**
     * The OCID of the compartment containing the DR Protection Group.  Example: `ocid1.compartment.oc1..exampleocid1`
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    readonly disassociateTrigger: number;
    /**
     * The display name of the DR Protection Group.  Example: `EBS PHX DRPG`
     */
    readonly displayName: string;
    readonly drProtectionGroupId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
     */
    readonly id: string;
    /**
     * A message describing the DR Protection Group's current state in more detail.
     */
    readonly lifeCycleDetails: string;
    /**
     * Information about an Object Storage log location for a DR Protection Group.
     */
    readonly logLocations: outputs.DisasterRecovery.GetDrProtectionGroupLogLocation[];
    /**
     * A list of DR Protection Group members.
     */
    readonly members: outputs.DisasterRecovery.GetDrProtectionGroupMember[];
    /**
     * The OCID of the peer (remote) DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
     */
    readonly peerId: string;
    /**
     * The region of the peer (remote) DR Protection Group.  Example: `us-ashburn-1`
     */
    readonly peerRegion: string;
    /**
     * The role of the DR Protection Group.
     */
    readonly role: string;
    /**
     * The current state of the DR Protection Group.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The date and time the DR Protection Group was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     */
    readonly timeCreated: string;
    /**
     * The date and time the DR Protection Group was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Dr Protection Group resource in Oracle Cloud Infrastructure Disaster Recovery service.
 *
 * Get the DR Protection Group identified by *drProtectionGroupId*.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrProtectionGroup = oci.DisasterRecovery.getDrProtectionGroup({
 *     drProtectionGroupId: oci_disaster_recovery_dr_protection_group.test_dr_protection_group.id,
 * });
 * ```
 */
export function getDrProtectionGroupOutput(args: GetDrProtectionGroupOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDrProtectionGroupResult> {
    return pulumi.output(args).apply((a: any) => getDrProtectionGroup(a, opts))
}

/**
 * A collection of arguments for invoking getDrProtectionGroup.
 */
export interface GetDrProtectionGroupOutputArgs {
    /**
     * The OCID of the DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     */
    drProtectionGroupId: pulumi.Input<string>;
}