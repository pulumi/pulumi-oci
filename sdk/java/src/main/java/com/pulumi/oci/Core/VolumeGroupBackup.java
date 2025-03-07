// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.VolumeGroupBackupArgs;
import com.pulumi.oci.Core.inputs.VolumeGroupBackupState;
import com.pulumi.oci.Core.outputs.VolumeGroupBackupSourceDetails;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Volume Group Backup resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a new backup volume group of the specified volume group.
 * For more information, see [Volume Groups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm).
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Core.VolumeGroupBackup;
 * import com.pulumi.oci.Core.VolumeGroupBackupArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testVolumeGroupBackup = new VolumeGroupBackup("testVolumeGroupBackup", VolumeGroupBackupArgs.builder()
 *             .volumeGroupId(testVolumeGroup.id())
 *             .compartmentId(compartmentId)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .displayName(volumeGroupBackupDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .type(volumeGroupBackupType)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * VolumeGroupBackups can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Core/volumeGroupBackup:VolumeGroupBackup test_volume_group_backup &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/volumeGroupBackup:VolumeGroupBackup")
public class VolumeGroupBackup extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     * 
     */
    @Export(name="expirationTime", refs={String.class}, tree="[0]")
    private Output<String> expirationTime;

    /**
     * @return The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     * 
     */
    public Output<String> expirationTime() {
        return this.expirationTime;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The aggregate size of the volume group backup, in GBs.
     * 
     */
    @Export(name="sizeInGbs", refs={String.class}, tree="[0]")
    private Output<String> sizeInGbs;

    /**
     * @return The aggregate size of the volume group backup, in GBs.
     * 
     */
    public Output<String> sizeInGbs() {
        return this.sizeInGbs;
    }
    /**
     * The aggregate size of the volume group backup, in MBs.
     * 
     */
    @Export(name="sizeInMbs", refs={String.class}, tree="[0]")
    private Output<String> sizeInMbs;

    /**
     * @return The aggregate size of the volume group backup, in MBs.
     * 
     */
    public Output<String> sizeInMbs() {
        return this.sizeInMbs;
    }
    /**
     * Details of the volume group backup source in the cloud.
     * 
     */
    @Export(name="sourceDetails", refs={VolumeGroupBackupSourceDetails.class}, tree="[0]")
    private Output</* @Nullable */ VolumeGroupBackupSourceDetails> sourceDetails;

    /**
     * @return Details of the volume group backup source in the cloud.
     * 
     */
    public Output<Optional<VolumeGroupBackupSourceDetails>> sourceDetails() {
        return Codegen.optional(this.sourceDetails);
    }
    /**
     * Specifies whether the volume group backup was created manually, or via scheduled backup policy.
     * 
     */
    @Export(name="sourceType", refs={String.class}, tree="[0]")
    private Output<String> sourceType;

    /**
     * @return Specifies whether the volume group backup was created manually, or via scheduled backup policy.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }
    /**
     * The OCID of the source volume group backup.
     * 
     */
    @Export(name="sourceVolumeGroupBackupId", refs={String.class}, tree="[0]")
    private Output<String> sourceVolumeGroupBackupId;

    /**
     * @return The OCID of the source volume group backup.
     * 
     */
    public Output<String> sourceVolumeGroupBackupId() {
        return this.sourceVolumeGroupBackupId;
    }
    /**
     * The current state of a volume group backup.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of a volume group backup.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeRequestReceived", refs={String.class}, tree="[0]")
    private Output<String> timeRequestReceived;

    /**
     * @return The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeRequestReceived() {
        return this.timeRequestReceived;
    }
    /**
     * The type of backup to create. If omitted, defaults to incremental.
     * * Allowed values are :
     * * FULL
     * * INCREMENTAL
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return The type of backup to create. If omitted, defaults to incremental.
     * * Allowed values are :
     * * FULL
     * * INCREMENTAL
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `size_in_gbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     * 
     */
    @Export(name="uniqueSizeInGbs", refs={String.class}, tree="[0]")
    private Output<String> uniqueSizeInGbs;

    /**
     * @return The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `size_in_gbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     * 
     */
    public Output<String> uniqueSizeInGbs() {
        return this.uniqueSizeInGbs;
    }
    /**
     * The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `size_in_mbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     * 
     */
    @Export(name="uniqueSizeInMbs", refs={String.class}, tree="[0]")
    private Output<String> uniqueSizeInMbs;

    /**
     * @return The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `size_in_mbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     * 
     */
    public Output<String> uniqueSizeInMbs() {
        return this.uniqueSizeInMbs;
    }
    /**
     * OCIDs for the volume backups in this volume group backup.
     * 
     */
    @Export(name="volumeBackupIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> volumeBackupIds;

    /**
     * @return OCIDs for the volume backups in this volume group backup.
     * 
     */
    public Output<List<String>> volumeBackupIds() {
        return this.volumeBackupIds;
    }
    /**
     * The OCID of the volume group that needs to be backed up.
     * 
     */
    @Export(name="volumeGroupId", refs={String.class}, tree="[0]")
    private Output<String> volumeGroupId;

    /**
     * @return The OCID of the volume group that needs to be backed up.
     * 
     */
    public Output<String> volumeGroupId() {
        return this.volumeGroupId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VolumeGroupBackup(java.lang.String name) {
        this(name, VolumeGroupBackupArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VolumeGroupBackup(java.lang.String name, @Nullable VolumeGroupBackupArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VolumeGroupBackup(java.lang.String name, @Nullable VolumeGroupBackupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeGroupBackup:VolumeGroupBackup", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private VolumeGroupBackup(java.lang.String name, Output<java.lang.String> id, @Nullable VolumeGroupBackupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeGroupBackup:VolumeGroupBackup", name, state, makeResourceOptions(options, id), false);
    }

    private static VolumeGroupBackupArgs makeArgs(@Nullable VolumeGroupBackupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? VolumeGroupBackupArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static VolumeGroupBackup get(java.lang.String name, Output<java.lang.String> id, @Nullable VolumeGroupBackupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VolumeGroupBackup(name, id, state, options);
    }
}
