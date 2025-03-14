// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FileStorage.FilesystemSnapshotPolicyArgs;
import com.pulumi.oci.FileStorage.inputs.FilesystemSnapshotPolicyState;
import com.pulumi.oci.FileStorage.outputs.FilesystemSnapshotPolicyLock;
import com.pulumi.oci.FileStorage.outputs.FilesystemSnapshotPolicySchedule;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Filesystem Snapshot Policy resource in Oracle Cloud Infrastructure File Storage service.
 * 
 * Creates a new file system snapshot policy in the specified compartment and
 * availability domain.
 * 
 * After you create a file system snapshot policy, you can associate it with
 * file systems.
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
 * import com.pulumi.oci.FileStorage.FilesystemSnapshotPolicy;
 * import com.pulumi.oci.FileStorage.FilesystemSnapshotPolicyArgs;
 * import com.pulumi.oci.FileStorage.inputs.FilesystemSnapshotPolicyLockArgs;
 * import com.pulumi.oci.FileStorage.inputs.FilesystemSnapshotPolicyScheduleArgs;
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
 *         var testFilesystemSnapshotPolicy = new FilesystemSnapshotPolicy("testFilesystemSnapshotPolicy", FilesystemSnapshotPolicyArgs.builder()
 *             .availabilityDomain(filesystemSnapshotPolicyAvailabilityDomain)
 *             .compartmentId(compartmentId)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .displayName(filesystemSnapshotPolicyDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .locks(FilesystemSnapshotPolicyLockArgs.builder()
 *                 .type(filesystemSnapshotPolicyLocksType)
 *                 .message(filesystemSnapshotPolicyLocksMessage)
 *                 .relatedResourceId(testResource.id())
 *                 .timeCreated(filesystemSnapshotPolicyLocksTimeCreated)
 *                 .build())
 *             .policyPrefix(filesystemSnapshotPolicyPolicyPrefix)
 *             .schedules(FilesystemSnapshotPolicyScheduleArgs.builder()
 *                 .period(filesystemSnapshotPolicySchedulesPeriod)
 *                 .timeZone(filesystemSnapshotPolicySchedulesTimeZone)
 *                 .dayOfMonth(filesystemSnapshotPolicySchedulesDayOfMonth)
 *                 .dayOfWeek(filesystemSnapshotPolicySchedulesDayOfWeek)
 *                 .hourOfDay(filesystemSnapshotPolicySchedulesHourOfDay)
 *                 .month(filesystemSnapshotPolicySchedulesMonth)
 *                 .retentionDurationInSeconds(filesystemSnapshotPolicySchedulesRetentionDurationInSeconds)
 *                 .schedulePrefix(filesystemSnapshotPolicySchedulesSchedulePrefix)
 *                 .timeScheduleStart(filesystemSnapshotPolicySchedulesTimeScheduleStart)
 *                 .build())
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
 * FilesystemSnapshotPolicies can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:FileStorage/filesystemSnapshotPolicy:FilesystemSnapshotPolicy test_filesystem_snapshot_policy &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FileStorage/filesystemSnapshotPolicy:FilesystemSnapshotPolicy")
public class FilesystemSnapshotPolicy extends com.pulumi.resources.CustomResource {
    /**
     * The availability domain that the file system snapshot policy is in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Export(name="availabilityDomain", refs={String.class}, tree="[0]")
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain that the file system snapshot policy is in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system snapshot policy.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system snapshot policy.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `policy1`
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `policy1`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    @Export(name="isLockOverride", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isLockOverride;

    public Output<Boolean> isLockOverride() {
        return this.isLockOverride;
    }
    /**
     * Locks associated with this resource.
     * 
     */
    @Export(name="locks", refs={List.class,FilesystemSnapshotPolicyLock.class}, tree="[0,1]")
    private Output<List<FilesystemSnapshotPolicyLock>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Output<List<FilesystemSnapshotPolicyLock>> locks() {
        return this.locks;
    }
    /**
     * (Updatable) The prefix to apply to all snapshots created by this policy.  Example: `acme`
     * 
     */
    @Export(name="policyPrefix", refs={String.class}, tree="[0]")
    private Output<String> policyPrefix;

    /**
     * @return (Updatable) The prefix to apply to all snapshots created by this policy.  Example: `acme`
     * 
     */
    public Output<String> policyPrefix() {
        return this.policyPrefix;
    }
    /**
     * (Updatable) The list of associated snapshot schedules. A maximum of 10 schedules can be associated with a policy.
     * 
     * If using the CLI, provide the schedule as a list of JSON strings, with the list wrapped in quotation marks, i.e. ```--schedules &#39;[{&#34;timeZone&#34;:&#34;UTC&#34;,&#34;period&#34;:&#34;DAILY&#34;,&#34;hourOfDay&#34;:18},{&#34;timeZone&#34;:&#34;UTC&#34;,&#34;period&#34;:&#34;HOURLY&#34;}]&#39;```
     * 
     */
    @Export(name="schedules", refs={List.class,FilesystemSnapshotPolicySchedule.class}, tree="[0,1]")
    private Output<List<FilesystemSnapshotPolicySchedule>> schedules;

    /**
     * @return (Updatable) The list of associated snapshot schedules. A maximum of 10 schedules can be associated with a policy.
     * 
     * If using the CLI, provide the schedule as a list of JSON strings, with the list wrapped in quotation marks, i.e. ```--schedules &#39;[{&#34;timeZone&#34;:&#34;UTC&#34;,&#34;period&#34;:&#34;DAILY&#34;,&#34;hourOfDay&#34;:18},{&#34;timeZone&#34;:&#34;UTC&#34;,&#34;period&#34;:&#34;HOURLY&#34;}]&#39;```
     * 
     */
    public Output<List<FilesystemSnapshotPolicySchedule>> schedules() {
        return this.schedules;
    }
    /**
     * (Updatable) The target state for the Filesystem Snapshot Policy. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return (Updatable) The target state for the Filesystem Snapshot Policy. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the file system snapshot policy was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the file system snapshot policy was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public FilesystemSnapshotPolicy(java.lang.String name) {
        this(name, FilesystemSnapshotPolicyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public FilesystemSnapshotPolicy(java.lang.String name, FilesystemSnapshotPolicyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public FilesystemSnapshotPolicy(java.lang.String name, FilesystemSnapshotPolicyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FileStorage/filesystemSnapshotPolicy:FilesystemSnapshotPolicy", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private FilesystemSnapshotPolicy(java.lang.String name, Output<java.lang.String> id, @Nullable FilesystemSnapshotPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FileStorage/filesystemSnapshotPolicy:FilesystemSnapshotPolicy", name, state, makeResourceOptions(options, id), false);
    }

    private static FilesystemSnapshotPolicyArgs makeArgs(FilesystemSnapshotPolicyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? FilesystemSnapshotPolicyArgs.Empty : args;
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
    public static FilesystemSnapshotPolicy get(java.lang.String name, Output<java.lang.String> id, @Nullable FilesystemSnapshotPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new FilesystemSnapshotPolicy(name, id, state, options);
    }
}
