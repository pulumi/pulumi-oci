// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CloudGuard.DetectorRecipeArgs;
import com.pulumi.oci.CloudGuard.inputs.DetectorRecipeState;
import com.pulumi.oci.CloudGuard.outputs.DetectorRecipeDetectorRule;
import com.pulumi.oci.CloudGuard.outputs.DetectorRecipeEffectiveDetectorRule;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
 * 
 * Creates a DetectorRecipe
 * 
 * ## Import
 * 
 * DetectorRecipes can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:CloudGuard/detectorRecipe:DetectorRecipe test_detector_recipe &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CloudGuard/detectorRecipe:DetectorRecipe")
public class DetectorRecipe extends com.pulumi.resources.CustomResource {
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
     * (Updatable) DetectorRecipe Description
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) DetectorRecipe Description
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * detector for the rule
     * 
     */
    @Export(name="detector", type=String.class, parameters={})
    private Output<String> detector;

    /**
     * @return detector for the rule
     * 
     */
    public Output<String> detector() {
        return this.detector;
    }
    /**
     * (Updatable) Detector Rules to override from source detector recipe
     * 
     */
    @Export(name="detectorRules", type=List.class, parameters={DetectorRecipeDetectorRule.class})
    private Output<List<DetectorRecipeDetectorRule>> detectorRules;

    /**
     * @return (Updatable) Detector Rules to override from source detector recipe
     * 
     */
    public Output<List<DetectorRecipeDetectorRule>> detectorRules() {
        return this.detectorRules;
    }
    /**
     * (Updatable) DetectorRecipe Display Name
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) DetectorRecipe Display Name
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * List of effective detector rules for the detector type for recipe after applying defaults
     * 
     */
    @Export(name="effectiveDetectorRules", type=List.class, parameters={DetectorRecipeEffectiveDetectorRule.class})
    private Output<List<DetectorRecipeEffectiveDetectorRule>> effectiveDetectorRules;

    /**
     * @return List of effective detector rules for the detector type for recipe after applying defaults
     * 
     */
    public Output<List<DetectorRecipeEffectiveDetectorRule>> effectiveDetectorRules() {
        return this.effectiveDetectorRules;
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
     * Owner of detector recipe
     * 
     */
    @Export(name="owner", type=String.class, parameters={})
    private Output<String> owner;

    /**
     * @return Owner of detector recipe
     * 
     */
    public Output<String> owner() {
        return this.owner;
    }
    /**
     * The id of the source detector recipe.
     * 
     */
    @Export(name="sourceDetectorRecipeId", type=String.class, parameters={})
    private Output<String> sourceDetectorRecipeId;

    /**
     * @return The id of the source detector recipe.
     * 
     */
    public Output<String> sourceDetectorRecipeId() {
        return this.sourceDetectorRecipeId;
    }
    /**
     * The current state of the resource.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the detector recipe was created. Format defined by RFC3339.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the detector recipe was created. Format defined by RFC3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the detector recipe was updated. Format defined by RFC3339.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the detector recipe was updated. Format defined by RFC3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DetectorRecipe(String name) {
        this(name, DetectorRecipeArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DetectorRecipe(String name, DetectorRecipeArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DetectorRecipe(String name, DetectorRecipeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudGuard/detectorRecipe:DetectorRecipe", name, args == null ? DetectorRecipeArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DetectorRecipe(String name, Output<String> id, @Nullable DetectorRecipeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudGuard/detectorRecipe:DetectorRecipe", name, state, makeResourceOptions(options, id));
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
    public static DetectorRecipe get(String name, Output<String> id, @Nullable DetectorRecipeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DetectorRecipe(name, id, state, options);
    }
}
