// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.RecoveryMod.ProtectionPolicyArgs;
import com.pulumi.oci.RecoveryMod.inputs.ProtectionPolicyState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Protection Policy resource in Oracle Cloud Infrastructure Recovery service.
 * 
 * Creates a new Protection Policy.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.RecoveryMod.ProtectionPolicy;
 * import com.pulumi.oci.RecoveryMod.ProtectionPolicyArgs;
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
 *         var testProtectionPolicy = new ProtectionPolicy(&#34;testProtectionPolicy&#34;, ProtectionPolicyArgs.builder()        
 *             .backupRetentionPeriodInDays(var_.protection_policy_backup_retention_period_in_days())
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.protection_policy_display_name())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * ProtectionPolicies can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:RecoveryMod/protectionPolicy:ProtectionPolicy test_protection_policy &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:RecoveryMod/protectionPolicy:ProtectionPolicy")
public class ProtectionPolicy extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The maximum number of days to retain backups for a protected database.
     * 
     */
    @Export(name="backupRetentionPeriodInDays", type=Integer.class, parameters={})
    private Output<Integer> backupRetentionPeriodInDays;

    /**
     * @return (Updatable) The maximum number of days to retain backups for a protected database.
     * 
     */
    public Output<Integer> backupRetentionPeriodInDays() {
        return this.backupRetentionPeriodInDays;
    }
    /**
     * (Updatable) Compartment Identifier
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user provided name for the protection policy. The &#39;displayName&#39; does not have to be unique, and it can be modified. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user provided name for the protection policy. The &#39;displayName&#39; does not have to be unique, and it can be modified. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
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
     * Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
     * 
     */
    @Export(name="isPredefinedPolicy", type=Boolean.class, parameters={})
    private Output<Boolean> isPredefinedPolicy;

    /**
     * @return Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
     * 
     */
    public Output<Boolean> isPredefinedPolicy() {
        return this.isPredefinedPolicy;
    }
    /**
     * Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The current state of the protection policy. Allowed values are:
     * * CREATING
     * * UPDATING
     * * ACTIVE
     * * DELETING
     * * DELETED
     * * FAILED
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the protection policy. Allowed values are:
     * * CREATING
     * * UPDATING
     * * ACTIVE
     * * DELETING
     * * DELETED
     * * FAILED
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: &#39;2020-05-22T21:10:29.600Z&#39;.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: &#39;2020-05-22T21:10:29.600Z&#39;.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: &#39;2020-05-22T21:10:29.600Z&#39;.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: &#39;2020-05-22T21:10:29.600Z&#39;.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ProtectionPolicy(String name) {
        this(name, ProtectionPolicyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ProtectionPolicy(String name, ProtectionPolicyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ProtectionPolicy(String name, ProtectionPolicyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:RecoveryMod/protectionPolicy:ProtectionPolicy", name, args == null ? ProtectionPolicyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ProtectionPolicy(String name, Output<String> id, @Nullable ProtectionPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:RecoveryMod/protectionPolicy:ProtectionPolicy", name, state, makeResourceOptions(options, id));
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
    public static ProtectionPolicy get(String name, Output<String> id, @Nullable ProtectionPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ProtectionPolicy(name, id, state, options);
    }
}