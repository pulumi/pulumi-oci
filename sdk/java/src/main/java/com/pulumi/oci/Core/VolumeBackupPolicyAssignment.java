// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.VolumeBackupPolicyAssignmentArgs;
import com.pulumi.oci.Core.inputs.VolumeBackupPolicyAssignmentState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service.
 * 
 * Assigns a volume backup policy to the specified volume. Note that a given volume can
 * only have one backup policy assigned to it. If this operation is used for a volume that already
 * has a different backup policy assigned, the prior backup policy will be silently unassigned.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * VolumeBackupPolicyAssignments can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment test_volume_backup_policy_assignment &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment")
public class VolumeBackupPolicyAssignment extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the volume to assign the policy to.
     * 
     */
    @Export(name="assetId", type=String.class, parameters={})
    private Output<String> assetId;

    /**
     * @return The OCID of the volume to assign the policy to.
     * 
     */
    public Output<String> assetId() {
        return this.assetId;
    }
    /**
     * The OCID of the volume backup policy to assign to the volume.
     * 
     */
    @Export(name="policyId", type=String.class, parameters={})
    private Output<String> policyId;

    /**
     * @return The OCID of the volume backup policy to assign to the volume.
     * 
     */
    public Output<String> policyId() {
        return this.policyId;
    }
    /**
     * The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VolumeBackupPolicyAssignment(String name) {
        this(name, VolumeBackupPolicyAssignmentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VolumeBackupPolicyAssignment(String name, VolumeBackupPolicyAssignmentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VolumeBackupPolicyAssignment(String name, VolumeBackupPolicyAssignmentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment", name, args == null ? VolumeBackupPolicyAssignmentArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private VolumeBackupPolicyAssignment(String name, Output<String> id, @Nullable VolumeBackupPolicyAssignmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static VolumeBackupPolicyAssignment get(String name, Output<String> id, @Nullable VolumeBackupPolicyAssignmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VolumeBackupPolicyAssignment(name, id, state, options);
    }
}
