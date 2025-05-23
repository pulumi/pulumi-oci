// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.GenerativeAi.DedicatedAiClusterArgs;
import com.pulumi.oci.GenerativeAi.inputs.DedicatedAiClusterState;
import com.pulumi.oci.GenerativeAi.outputs.DedicatedAiClusterCapacity;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Dedicated Ai Cluster resource in Oracle Cloud Infrastructure Generative AI service.
 * 
 * Creates a dedicated AI cluster.
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
 * import com.pulumi.oci.GenerativeAi.DedicatedAiCluster;
 * import com.pulumi.oci.GenerativeAi.DedicatedAiClusterArgs;
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
 *         var testDedicatedAiCluster = new DedicatedAiCluster("testDedicatedAiCluster", DedicatedAiClusterArgs.builder()
 *             .compartmentId(compartmentId)
 *             .type(dedicatedAiClusterType)
 *             .unitCount(dedicatedAiClusterUnitCount)
 *             .unitShape(dedicatedAiClusterUnitShape)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .description(dedicatedAiClusterDescription)
 *             .displayName(dedicatedAiClusterDisplayName)
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
 * DedicatedAiClusters can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:GenerativeAi/dedicatedAiCluster:DedicatedAiCluster test_dedicated_ai_cluster &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:GenerativeAi/dedicatedAiCluster:DedicatedAiCluster")
public class DedicatedAiCluster extends com.pulumi.resources.CustomResource {
    /**
     * The total capacity for a dedicated AI cluster.
     * 
     */
    @Export(name="capacities", refs={List.class,DedicatedAiClusterCapacity.class}, tree="[0,1]")
    private Output<List<DedicatedAiClusterCapacity>> capacities;

    /**
     * @return The total capacity for a dedicated AI cluster.
     * 
     */
    public Output<List<DedicatedAiClusterCapacity>> capacities() {
        return this.capacities;
    }
    /**
     * (Updatable) The compartment OCID to create the dedicated AI cluster in.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The compartment OCID to create the dedicated AI cluster in.
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
     * (Updatable) An optional description of the dedicated AI cluster.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) An optional description of the dedicated AI cluster.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
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
     * A message describing the current state with detail that can provide actionable information.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state with detail that can provide actionable information.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The current state of the dedicated AI cluster.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the dedicated AI cluster.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the dedicated AI cluster was created, in the format defined by RFC 3339
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the dedicated AI cluster was created, in the format defined by RFC 3339
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the dedicated AI cluster was updated, in the format defined by RFC 3339
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the dedicated AI cluster was updated, in the format defined by RFC 3339
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The dedicated AI cluster type indicating whether this is a fine-tuning/training processor or hosting/inference processor.
     * 
     * Allowed values are:
     * * HOSTING
     * * FINE_TUNING
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return The dedicated AI cluster type indicating whether this is a fine-tuning/training processor or hosting/inference processor.
     * 
     * Allowed values are:
     * * HOSTING
     * * FINE_TUNING
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * (Updatable) The number of dedicated units in this AI cluster.
     * 
     */
    @Export(name="unitCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> unitCount;

    /**
     * @return (Updatable) The number of dedicated units in this AI cluster.
     * 
     */
    public Output<Integer> unitCount() {
        return this.unitCount;
    }
    /**
     * The shape of dedicated unit in this AI cluster. The underlying hardware configuration is hidden from customers.
     * 
     * Allowed values are:
     * * LARGE_COHERE
     * * LARGE_COHERE_V2
     * * SMALL_COHERE
     * * SMALL_COHERE_V2
     * * SMALL_COHERE_4
     * * EMBED_COHERE
     * * LLAMA2_70
     * * LARGE_GENERIC
     * * LARGE_COHERE_V2_2
     * * LARGE_GENERIC_4
     * * SMALL_GENERIC_V2
     * * LARGE_GENERIC_2
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="unitShape", refs={String.class}, tree="[0]")
    private Output<String> unitShape;

    /**
     * @return The shape of dedicated unit in this AI cluster. The underlying hardware configuration is hidden from customers.
     * 
     * Allowed values are:
     * * LARGE_COHERE
     * * LARGE_COHERE_V2
     * * SMALL_COHERE
     * * SMALL_COHERE_V2
     * * SMALL_COHERE_4
     * * EMBED_COHERE
     * * LLAMA2_70
     * * LARGE_GENERIC
     * * LARGE_COHERE_V2_2
     * * LARGE_GENERIC_4
     * * SMALL_GENERIC_V2
     * * LARGE_GENERIC_2
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> unitShape() {
        return this.unitShape;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DedicatedAiCluster(java.lang.String name) {
        this(name, DedicatedAiClusterArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DedicatedAiCluster(java.lang.String name, DedicatedAiClusterArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DedicatedAiCluster(java.lang.String name, DedicatedAiClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:GenerativeAi/dedicatedAiCluster:DedicatedAiCluster", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DedicatedAiCluster(java.lang.String name, Output<java.lang.String> id, @Nullable DedicatedAiClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:GenerativeAi/dedicatedAiCluster:DedicatedAiCluster", name, state, makeResourceOptions(options, id), false);
    }

    private static DedicatedAiClusterArgs makeArgs(DedicatedAiClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DedicatedAiClusterArgs.Empty : args;
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
    public static DedicatedAiCluster get(java.lang.String name, Output<java.lang.String> id, @Nullable DedicatedAiClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DedicatedAiCluster(name, id, state, options);
    }
}
