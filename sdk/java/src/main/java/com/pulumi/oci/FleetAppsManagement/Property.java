// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FleetAppsManagement.PropertyArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.PropertyState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Property resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 * 
 * Create a business-specific metadata property in Fleet Application Management.
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
 * import com.pulumi.oci.FleetAppsManagement.Property;
 * import com.pulumi.oci.FleetAppsManagement.PropertyArgs;
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
 *         var testProperty = new Property("testProperty", PropertyArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(propertyDisplayName)
 *             .selection(propertySelection)
 *             .valueType(propertyValueType)
 *             .values(propertyValues)
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
 * Properties can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:FleetAppsManagement/property:Property test_property &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FleetAppsManagement/property:Property")
public class Property extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment OCID
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment OCID
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Associated region
     * 
     */
    @Export(name="resourceRegion", refs={String.class}, tree="[0]")
    private Output<String> resourceRegion;

    /**
     * @return Associated region
     * 
     */
    public Output<String> resourceRegion() {
        return this.resourceRegion;
    }
    /**
     * The scope of the property.
     * 
     */
    @Export(name="scope", refs={String.class}, tree="[0]")
    private Output<String> scope;

    /**
     * @return The scope of the property.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }
    /**
     * (Updatable) Text selection of the property.
     * 
     */
    @Export(name="selection", refs={String.class}, tree="[0]")
    private Output<String> selection;

    /**
     * @return (Updatable) Text selection of the property.
     * 
     */
    public Output<String> selection() {
        return this.selection;
    }
    /**
     * The current state of the Property.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Property.
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
     * The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The type of the property.
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return The type of the property.
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * (Updatable) Format of the value.
     * 
     */
    @Export(name="valueType", refs={String.class}, tree="[0]")
    private Output<String> valueType;

    /**
     * @return (Updatable) Format of the value.
     * 
     */
    public Output<String> valueType() {
        return this.valueType;
    }
    /**
     * (Updatable) Values of the property (must be a single value if selection = &#39;SINGLE_CHOICE&#39;).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="values", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> values;

    /**
     * @return (Updatable) Values of the property (must be a single value if selection = &#39;SINGLE_CHOICE&#39;).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<String>> values() {
        return this.values;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Property(java.lang.String name) {
        this(name, PropertyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Property(java.lang.String name, PropertyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Property(java.lang.String name, PropertyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FleetAppsManagement/property:Property", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Property(java.lang.String name, Output<java.lang.String> id, @Nullable PropertyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FleetAppsManagement/property:Property", name, state, makeResourceOptions(options, id), false);
    }

    private static PropertyArgs makeArgs(PropertyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? PropertyArgs.Empty : args;
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
    public static Property get(java.lang.String name, Output<java.lang.String> id, @Nullable PropertyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Property(name, id, state, options);
    }
}
