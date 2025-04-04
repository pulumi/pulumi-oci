// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CloudBridge.DiscoveryScheduleArgs;
import com.pulumi.oci.CloudBridge.inputs.DiscoveryScheduleState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Discovery Schedule resource in Oracle Cloud Infrastructure Cloud Bridge service.
 * 
 * Creates the discovery schedule.
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
 * import com.pulumi.oci.CloudBridge.DiscoverySchedule;
 * import com.pulumi.oci.CloudBridge.DiscoveryScheduleArgs;
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
 *         var testDiscoverySchedule = new DiscoverySchedule("testDiscoverySchedule", DiscoveryScheduleArgs.builder()
 *             .compartmentId(compartmentId)
 *             .executionRecurrences(discoveryScheduleExecutionRecurrences)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .displayName(discoveryScheduleDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
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
 * DiscoverySchedules can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:CloudBridge/discoverySchedule:DiscoverySchedule test_discovery_schedule &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CloudBridge/discoverySchedule:DiscoverySchedule")
public class DiscoverySchedule extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the discovery schedule is created.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the discovery schedule is created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name for the discovery schedule. Does not have to be unique, and it&#39;s mutable. Avoid entering confidential information. The name is generated by the service if it is not explicitly provided.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the discovery schedule. Does not have to be unique, and it&#39;s mutable. Avoid entering confidential information. The name is generated by the service if it is not explicitly provided.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Recurrence specification for the discovery schedule execution.
     * 
     */
    @Export(name="executionRecurrences", refs={String.class}, tree="[0]")
    private Output<String> executionRecurrences;

    /**
     * @return (Updatable) Recurrence specification for the discovery schedule execution.
     * 
     */
    public Output<String> executionRecurrences() {
        return this.executionRecurrences;
    }
    /**
     * (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The detailed state of the discovery schedule.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return The detailed state of the discovery schedule.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Current state of the discovery schedule.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return Current state of the discovery schedule.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when the discovery schedule was created in RFC3339 format.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when the discovery schedule was created in RFC3339 format.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the discovery schedule was last updated in RFC3339 format.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when the discovery schedule was last updated in RFC3339 format.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DiscoverySchedule(java.lang.String name) {
        this(name, DiscoveryScheduleArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DiscoverySchedule(java.lang.String name, DiscoveryScheduleArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DiscoverySchedule(java.lang.String name, DiscoveryScheduleArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudBridge/discoverySchedule:DiscoverySchedule", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DiscoverySchedule(java.lang.String name, Output<java.lang.String> id, @Nullable DiscoveryScheduleState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudBridge/discoverySchedule:DiscoverySchedule", name, state, makeResourceOptions(options, id), false);
    }

    private static DiscoveryScheduleArgs makeArgs(DiscoveryScheduleArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DiscoveryScheduleArgs.Empty : args;
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
    public static DiscoverySchedule get(java.lang.String name, Output<java.lang.String> id, @Nullable DiscoveryScheduleState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DiscoverySchedule(name, id, state, options);
    }
}
