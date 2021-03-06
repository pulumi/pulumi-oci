// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.VolumeBackupPolicyArgs;
import com.pulumi.oci.Core.inputs.VolumeBackupPolicyState;
import com.pulumi.oci.Core.outputs.VolumeBackupPolicySchedule;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Volume Backup Policy resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a new user defined backup policy.
 * 
 * For more information about Oracle defined backup policies and user defined backup policies,
 * see [Policy-Based Backups](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm).
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * VolumeBackupPolicies can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/volumeBackupPolicy:VolumeBackupPolicy test_volume_backup_policy &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/volumeBackupPolicy:VolumeBackupPolicy")
public class VolumeBackupPolicy extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) The paired destination region for copying scheduled backups to. Example: `us-ashburn-1`. See [Region Pairs](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm#RegionPairs) for details about paired regions.
     * 
     */
    @Export(name="destinationRegion", type=String.class, parameters={})
    private Output<String> destinationRegion;

    /**
     * @return (Updatable) The paired destination region for copying scheduled backups to. Example: `us-ashburn-1`. See [Region Pairs](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm#RegionPairs) for details about paired regions.
     * 
     */
    public Output<String> destinationRegion() {
        return this.destinationRegion;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The collection of schedules for the volume backup policy. See see [Schedules](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm#schedules) in [Policy-Based Backups](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm) for more information.
     * 
     */
    @Export(name="schedules", type=List.class, parameters={VolumeBackupPolicySchedule.class})
    private Output</* @Nullable */ List<VolumeBackupPolicySchedule>> schedules;

    /**
     * @return (Updatable) The collection of schedules for the volume backup policy. See see [Schedules](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm#schedules) in [Policy-Based Backups](https://docs.cloud.oracle.com/iaas/Content/Block/Tasks/schedulingvolumebackups.htm) for more information.
     * 
     */
    public Output<Optional<List<VolumeBackupPolicySchedule>>> schedules() {
        return Codegen.optional(this.schedules);
    }
    /**
     * The date and time the volume backup policy was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the volume backup policy was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VolumeBackupPolicy(String name) {
        this(name, VolumeBackupPolicyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VolumeBackupPolicy(String name, VolumeBackupPolicyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VolumeBackupPolicy(String name, VolumeBackupPolicyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeBackupPolicy:VolumeBackupPolicy", name, args == null ? VolumeBackupPolicyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private VolumeBackupPolicy(String name, Output<String> id, @Nullable VolumeBackupPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeBackupPolicy:VolumeBackupPolicy", name, state, makeResourceOptions(options, id));
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
    public static VolumeBackupPolicy get(String name, Output<String> id, @Nullable VolumeBackupPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VolumeBackupPolicy(name, id, state, options);
    }
}
