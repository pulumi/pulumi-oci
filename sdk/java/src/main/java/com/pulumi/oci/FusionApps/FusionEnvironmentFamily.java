// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FusionApps.FusionEnvironmentFamilyArgs;
import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentFamilyState;
import com.pulumi.oci.FusionApps.outputs.FusionEnvironmentFamilyFamilyMaintenancePolicy;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Fusion Environment Family resource in Oracle Cloud Infrastructure Fusion Apps service.
 * 
 * Creates a new FusionEnvironmentFamily.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.FusionApps.FusionEnvironmentFamily;
 * import com.pulumi.oci.FusionApps.FusionEnvironmentFamilyArgs;
 * import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentFamilyFamilyMaintenancePolicyArgs;
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
 *         var testFusionEnvironmentFamily = new FusionEnvironmentFamily(&#34;testFusionEnvironmentFamily&#34;, FusionEnvironmentFamilyArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.fusion_environment_family_display_name())
 *             .subscriptionIds(var_.fusion_environment_family_subscription_ids())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .familyMaintenancePolicy(FusionEnvironmentFamilyFamilyMaintenancePolicyArgs.builder()
 *                 .concurrentMaintenance(var_.fusion_environment_family_family_maintenance_policy_concurrent_maintenance())
 *                 .isMonthlyPatchingEnabled(var_.fusion_environment_family_family_maintenance_policy_is_monthly_patching_enabled())
 *                 .quarterlyUpgradeBeginTimes(var_.fusion_environment_family_family_maintenance_policy_quarterly_upgrade_begin_times())
 *                 .build())
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * FusionEnvironmentFamilies can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily test_fusion_environment_family &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily")
public class FusionEnvironmentFamily extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment where the environment family is located.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment where the environment family is located.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     * 
     */
    @Export(name="familyMaintenancePolicy", type=FusionEnvironmentFamilyFamilyMaintenancePolicy.class, parameters={})
    private Output<FusionEnvironmentFamilyFamilyMaintenancePolicy> familyMaintenancePolicy;

    /**
     * @return (Updatable) The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
     * 
     */
    public Output<FusionEnvironmentFamilyFamilyMaintenancePolicy> familyMaintenancePolicy() {
        return this.familyMaintenancePolicy;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * When set to True, a subscription update is required for the environment family.
     * 
     */
    @Export(name="isSubscriptionUpdateNeeded", type=Boolean.class, parameters={})
    private Output<Boolean> isSubscriptionUpdateNeeded;

    /**
     * @return When set to True, a subscription update is required for the environment family.
     * 
     */
    public Output<Boolean> isSubscriptionUpdateNeeded() {
        return this.isSubscriptionUpdateNeeded;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The current state of the FusionEnvironmentFamily.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the FusionEnvironmentFamily.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
     * 
     */
    @Export(name="subscriptionIds", type=List.class, parameters={String.class})
    private Output<List<String>> subscriptionIds;

    /**
     * @return (Updatable) The list of the IDs of the applications subscriptions that are associated with the environment family.
     * 
     */
    public Output<List<String>> subscriptionIds() {
        return this.subscriptionIds;
    }
    /**
     * Environment Specific Guid/ System Name
     * 
     */
    @Export(name="systemName", type=String.class, parameters={})
    private Output<String> systemName;

    /**
     * @return Environment Specific Guid/ System Name
     * 
     */
    public Output<String> systemName() {
        return this.systemName;
    }
    /**
     * The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output</* @Nullable */ String> timeUpdated;

    public Output<Optional<String>> timeUpdated() {
        return Codegen.optional(this.timeUpdated);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public FusionEnvironmentFamily(String name) {
        this(name, FusionEnvironmentFamilyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public FusionEnvironmentFamily(String name, FusionEnvironmentFamilyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public FusionEnvironmentFamily(String name, FusionEnvironmentFamilyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily", name, args == null ? FusionEnvironmentFamilyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private FusionEnvironmentFamily(String name, Output<String> id, @Nullable FusionEnvironmentFamilyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily", name, state, makeResourceOptions(options, id));
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
    public static FusionEnvironmentFamily get(String name, Output<String> id, @Nullable FusionEnvironmentFamilyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new FusionEnvironmentFamily(name, id, state, options);
    }
}