// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service.
 *
 * Assigns a volume backup policy to the specified volume. Note that a given volume can
 * only have one backup policy assigned to it. If this operation is used for a volume that already
 * has a different backup policy assigned, the prior backup policy will be silently unassigned.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolumeBackupPolicyAssignment = new oci.core.VolumeBackupPolicyAssignment("testVolumeBackupPolicyAssignment", {
 *     assetId: oci_core_volume.test_volume.id,
 *     policyId: oci_core_volume_backup_policy.test_volume_backup_policy.id,
 * });
 * ```
 *
 * ## Import
 *
 * VolumeBackupPolicyAssignments can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment test_volume_backup_policy_assignment "id"
 * ```
 */
export class VolumeBackupPolicyAssignment extends pulumi.CustomResource {
    /**
     * Get an existing VolumeBackupPolicyAssignment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VolumeBackupPolicyAssignmentState, opts?: pulumi.CustomResourceOptions): VolumeBackupPolicyAssignment {
        return new VolumeBackupPolicyAssignment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment';

    /**
     * Returns true if the given object is an instance of VolumeBackupPolicyAssignment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VolumeBackupPolicyAssignment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VolumeBackupPolicyAssignment.__pulumiType;
    }

    /**
     * The OCID of the volume to assign the policy to.
     */
    public readonly assetId!: pulumi.Output<string>;
    /**
     * The OCID of the volume backup policy to assign to the volume.
     */
    public readonly policyId!: pulumi.Output<string>;
    /**
     * The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a VolumeBackupPolicyAssignment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VolumeBackupPolicyAssignmentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VolumeBackupPolicyAssignmentArgs | VolumeBackupPolicyAssignmentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VolumeBackupPolicyAssignmentState | undefined;
            resourceInputs["assetId"] = state ? state.assetId : undefined;
            resourceInputs["policyId"] = state ? state.policyId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as VolumeBackupPolicyAssignmentArgs | undefined;
            if ((!args || args.assetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'assetId'");
            }
            if ((!args || args.policyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'policyId'");
            }
            resourceInputs["assetId"] = args ? args.assetId : undefined;
            resourceInputs["policyId"] = args ? args.policyId : undefined;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(VolumeBackupPolicyAssignment.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VolumeBackupPolicyAssignment resources.
 */
export interface VolumeBackupPolicyAssignmentState {
    /**
     * The OCID of the volume to assign the policy to.
     */
    assetId?: pulumi.Input<string>;
    /**
     * The OCID of the volume backup policy to assign to the volume.
     */
    policyId?: pulumi.Input<string>;
    /**
     * The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a VolumeBackupPolicyAssignment resource.
 */
export interface VolumeBackupPolicyAssignmentArgs {
    /**
     * The OCID of the volume to assign the policy to.
     */
    assetId: pulumi.Input<string>;
    /**
     * The OCID of the volume backup policy to assign to the volume.
     */
    policyId: pulumi.Input<string>;
}