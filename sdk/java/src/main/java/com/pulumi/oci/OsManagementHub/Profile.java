// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.ProfileArgs;
import com.pulumi.oci.OsManagementHub.inputs.ProfileState;
import com.pulumi.oci.OsManagementHub.outputs.ProfileLifecycleEnvironment;
import com.pulumi.oci.OsManagementHub.outputs.ProfileLifecycleStage;
import com.pulumi.oci.OsManagementHub.outputs.ProfileManagedInstanceGroup;
import com.pulumi.oci.OsManagementHub.outputs.ProfileSoftwareSource;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Profile resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Creates a registration profile. A profile defines the content applied to the instance when registering it with the service.
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
 * import com.pulumi.oci.OsManagementHub.Profile;
 * import com.pulumi.oci.OsManagementHub.ProfileArgs;
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
 *         var testProfile = new Profile("testProfile", ProfileArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(profileDisplayName)
 *             .profileType(profileProfileType)
 *             .archType(profileArchType)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .description(profileDescription)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .isDefaultProfile(profileIsDefaultProfile)
 *             .lifecycleStageId(testLifecycleStage.id())
 *             .managedInstanceGroupId(testManagedInstanceGroup.id())
 *             .managementStationId(testManagementStation.id())
 *             .osFamily(profileOsFamily)
 *             .registrationType(profileRegistrationType)
 *             .softwareSourceIds(profileSoftwareSourceIds)
 *             .vendorName(profileVendorName)
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
 * Profiles can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/profile:Profile test_profile &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/profile:Profile")
public class Profile extends com.pulumi.resources.CustomResource {
    /**
     * The architecture type.
     * 
     */
    @Export(name="archType", refs={String.class}, tree="[0]")
    private Output<String> archType;

    /**
     * @return The architecture type.
     * 
     */
    public Output<String> archType() {
        return this.archType;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the registration profile.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the registration profile.
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
     * (Updatable) User-specified description of the registration profile.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) User-specified description of the registration profile.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique and you can change the name later. Avoid entering  confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique and you can change the name later. Avoid entering  confidential information.
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
    /**
     * (Updatable) Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.
     * 
     */
    @Export(name="isDefaultProfile", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isDefaultProfile;

    /**
     * @return (Updatable) Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.
     * 
     */
    public Output<Boolean> isDefaultProfile() {
        return this.isDefaultProfile;
    }
    /**
     * Indicates if the profile was created by the service. OS Management Hub provides a limited set of standardized profiles that can be used to register Autonomous Linux or Windows instances.
     * 
     */
    @Export(name="isServiceProvidedProfile", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isServiceProvidedProfile;

    /**
     * @return Indicates if the profile was created by the service. OS Management Hub provides a limited set of standardized profiles that can be used to register Autonomous Linux or Windows instances.
     * 
     */
    public Output<Boolean> isServiceProvidedProfile() {
        return this.isServiceProvidedProfile;
    }
    /**
     * Provides identifying information for the specified lifecycle environment.
     * 
     */
    @Export(name="lifecycleEnvironments", refs={List.class,ProfileLifecycleEnvironment.class}, tree="[0,1]")
    private Output<List<ProfileLifecycleEnvironment>> lifecycleEnvironments;

    /**
     * @return Provides identifying information for the specified lifecycle environment.
     * 
     */
    public Output<List<ProfileLifecycleEnvironment>> lifecycleEnvironments() {
        return this.lifecycleEnvironments;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
     * 
     */
    @Export(name="lifecycleStageId", refs={String.class}, tree="[0]")
    private Output<String> lifecycleStageId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
     * 
     */
    public Output<String> lifecycleStageId() {
        return this.lifecycleStageId;
    }
    /**
     * Provides identifying information for the specified lifecycle stage.
     * 
     */
    @Export(name="lifecycleStages", refs={List.class,ProfileLifecycleStage.class}, tree="[0,1]")
    private Output<List<ProfileLifecycleStage>> lifecycleStages;

    /**
     * @return Provides identifying information for the specified lifecycle stage.
     * 
     */
    public Output<List<ProfileLifecycleStage>> lifecycleStages() {
        return this.lifecycleStages;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group that the instance will join after registration.
     * 
     */
    @Export(name="managedInstanceGroupId", refs={String.class}, tree="[0]")
    private Output<String> managedInstanceGroupId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group that the instance will join after registration.
     * 
     */
    public Output<String> managedInstanceGroupId() {
        return this.managedInstanceGroupId;
    }
    /**
     * Provides identifying information for the specified managed instance group.
     * 
     */
    @Export(name="managedInstanceGroups", refs={List.class,ProfileManagedInstanceGroup.class}, tree="[0,1]")
    private Output<List<ProfileManagedInstanceGroup>> managedInstanceGroups;

    /**
     * @return Provides identifying information for the specified managed instance group.
     * 
     */
    public Output<List<ProfileManagedInstanceGroup>> managedInstanceGroups() {
        return this.managedInstanceGroups;
    }
    /**
     * description: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station to associate  with an instance once registered. This is required when creating a profile for non-OCI instances.
     * 
     */
    @Export(name="managementStationId", refs={String.class}, tree="[0]")
    private Output<String> managementStationId;

    /**
     * @return description: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station to associate  with an instance once registered. This is required when creating a profile for non-OCI instances.
     * 
     */
    public Output<String> managementStationId() {
        return this.managementStationId;
    }
    /**
     * The operating system family.
     * 
     */
    @Export(name="osFamily", refs={String.class}, tree="[0]")
    private Output<String> osFamily;

    /**
     * @return The operating system family.
     * 
     */
    public Output<String> osFamily() {
        return this.osFamily;
    }
    /**
     * The type of profile.
     * 
     */
    @Export(name="profileType", refs={String.class}, tree="[0]")
    private Output<String> profileType;

    /**
     * @return The type of profile.
     * 
     */
    public Output<String> profileType() {
        return this.profileType;
    }
    /**
     * The version of the profile. The version is automatically incremented each time the profiled is edited.
     * 
     */
    @Export(name="profileVersion", refs={String.class}, tree="[0]")
    private Output<String> profileVersion;

    /**
     * @return The version of the profile. The version is automatically incremented each time the profiled is edited.
     * 
     */
    public Output<String> profileVersion() {
        return this.profileVersion;
    }
    /**
     * The type of instance to register.
     * 
     */
    @Export(name="registrationType", refs={String.class}, tree="[0]")
    private Output<String> registrationType;

    /**
     * @return The type of instance to register.
     * 
     */
    public Output<String> registrationType() {
        return this.registrationType;
    }
    /**
     * The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the registration profile will use.
     * 
     */
    @Export(name="softwareSourceIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> softwareSourceIds;

    /**
     * @return The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the registration profile will use.
     * 
     */
    public Output<List<String>> softwareSourceIds() {
        return this.softwareSourceIds;
    }
    /**
     * The list of software sources that the registration profile will use.
     * 
     */
    @Export(name="softwareSources", refs={List.class,ProfileSoftwareSource.class}, tree="[0,1]")
    private Output<List<ProfileSoftwareSource>> softwareSources;

    /**
     * @return The list of software sources that the registration profile will use.
     * 
     */
    public Output<List<ProfileSoftwareSource>> softwareSources() {
        return this.softwareSources;
    }
    /**
     * The current state of the registration profile.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the registration profile.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the registration profile was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the registration profile was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the registration profile was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    @Export(name="timeModified", refs={String.class}, tree="[0]")
    private Output<String> timeModified;

    /**
     * @return The time the registration profile was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public Output<String> timeModified() {
        return this.timeModified;
    }
    /**
     * The vendor of the operating system for the instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="vendorName", refs={String.class}, tree="[0]")
    private Output<String> vendorName;

    /**
     * @return The vendor of the operating system for the instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> vendorName() {
        return this.vendorName;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Profile(java.lang.String name) {
        this(name, ProfileArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Profile(java.lang.String name, ProfileArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Profile(java.lang.String name, ProfileArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profile:Profile", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Profile(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profile:Profile", name, state, makeResourceOptions(options, id), false);
    }

    private static ProfileArgs makeArgs(ProfileArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ProfileArgs.Empty : args;
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
    public static Profile get(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Profile(name, id, state, options);
    }
}
