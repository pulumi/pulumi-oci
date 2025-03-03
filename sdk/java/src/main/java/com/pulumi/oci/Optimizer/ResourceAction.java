// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Optimizer.ResourceActionArgs;
import com.pulumi.oci.Optimizer.inputs.ResourceActionState;
import com.pulumi.oci.Optimizer.outputs.ResourceActionAction;
import com.pulumi.oci.Utilities;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Resource Action resource in Oracle Cloud Infrastructure Optimizer service.
 * 
 * Updates the resource action that corresponds to the specified OCID.
 * Use this operation to implement the following actions:
 * 
 *   * Postpone resource action
 *   * Ignore resource action
 *   * Reactivate resource action
 * 
 * ## Import
 * 
 * ResourceActions can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Optimizer/resourceAction:ResourceAction test_resource_action &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Optimizer/resourceAction:ResourceAction")
public class ResourceAction extends com.pulumi.resources.CustomResource {
    /**
     * Details about the recommended action.
     * 
     */
    @Export(name="actions", refs={List.class,ResourceActionAction.class}, tree="[0,1]")
    private Output<List<ResourceActionAction>> actions;

    /**
     * @return Details about the recommended action.
     * 
     */
    public Output<List<ResourceActionAction>> actions() {
        return this.actions;
    }
    /**
     * The unique OCID associated with the category.
     * 
     */
    @Export(name="categoryId", refs={String.class}, tree="[0]")
    private Output<String> categoryId;

    /**
     * @return The unique OCID associated with the category.
     * 
     */
    public Output<String> categoryId() {
        return this.categoryId;
    }
    /**
     * The OCID of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The name associated with the compartment.
     * 
     */
    @Export(name="compartmentName", refs={String.class}, tree="[0]")
    private Output<String> compartmentName;

    /**
     * @return The name associated with the compartment.
     * 
     */
    public Output<String> compartmentName() {
        return this.compartmentName;
    }
    /**
     * The estimated cost savings, in dollars, for the resource action.
     * 
     */
    @Export(name="estimatedCostSaving", refs={Double.class}, tree="[0]")
    private Output<Double> estimatedCostSaving;

    /**
     * @return The estimated cost savings, in dollars, for the resource action.
     * 
     */
    public Output<Double> estimatedCostSaving() {
        return this.estimatedCostSaving;
    }
    /**
     * Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    @Export(name="extendedMetadata", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> extendedMetadata;

    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    public Output<Map<String,String>> extendedMetadata() {
        return this.extendedMetadata;
    }
    /**
     * Custom metadata key/value pairs for the resource action.
     * 
     */
    @Export(name="metadata", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> metadata;

    /**
     * @return Custom metadata key/value pairs for the resource action.
     * 
     */
    public Output<Map<String,String>> metadata() {
        return this.metadata;
    }
    /**
     * The name assigned to the resource.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return The name assigned to the resource.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The unique OCID associated with the recommendation.
     * 
     */
    @Export(name="recommendationId", refs={String.class}, tree="[0]")
    private Output<String> recommendationId;

    /**
     * @return The unique OCID associated with the recommendation.
     * 
     */
    public Output<String> recommendationId() {
        return this.recommendationId;
    }
    /**
     * The unique OCID associated with the resource action.
     * 
     */
    @Export(name="resourceActionId", refs={String.class}, tree="[0]")
    private Output<String> resourceActionId;

    /**
     * @return The unique OCID associated with the resource action.
     * 
     */
    public Output<String> resourceActionId() {
        return this.resourceActionId;
    }
    /**
     * The unique OCID associated with the resource.
     * 
     */
    @Export(name="resourceId", refs={String.class}, tree="[0]")
    private Output<String> resourceId;

    /**
     * @return The unique OCID associated with the resource.
     * 
     */
    public Output<String> resourceId() {
        return this.resourceId;
    }
    /**
     * The kind of resource.
     * 
     */
    @Export(name="resourceType", refs={String.class}, tree="[0]")
    private Output<String> resourceType;

    /**
     * @return The kind of resource.
     * 
     */
    public Output<String> resourceType() {
        return this.resourceType;
    }
    /**
     * The resource action&#39;s current state.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The resource action&#39;s current state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) The status of the resource action.
     * 
     */
    @Export(name="status", refs={String.class}, tree="[0]")
    private Output<String> status;

    /**
     * @return (Updatable) The status of the resource action.
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * The date and time the resource action details were created, in the format defined by RFC3339.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource action details were created, in the format defined by RFC3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time that the resource action entered its current status. The format is defined by RFC3339.
     * 
     */
    @Export(name="timeStatusBegin", refs={String.class}, tree="[0]")
    private Output<String> timeStatusBegin;

    /**
     * @return The date and time that the resource action entered its current status. The format is defined by RFC3339.
     * 
     */
    public Output<String> timeStatusBegin() {
        return this.timeStatusBegin;
    }
    /**
     * (Updatable) The date and time the current status will change. The format is defined by RFC3339.
     * 
     * For example, &#34;The current `postponed` status of the resource action will end and change to `pending` on this date and time.&#34;
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="timeStatusEnd", refs={String.class}, tree="[0]")
    private Output<String> timeStatusEnd;

    /**
     * @return (Updatable) The date and time the current status will change. The format is defined by RFC3339.
     * 
     * For example, &#34;The current `postponed` status of the resource action will end and change to `pending` on this date and time.&#34;
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> timeStatusEnd() {
        return this.timeStatusEnd;
    }
    /**
     * The date and time the resource action details were last updated, in the format defined by RFC3339.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource action details were last updated, in the format defined by RFC3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ResourceAction(java.lang.String name) {
        this(name, ResourceActionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ResourceAction(java.lang.String name, ResourceActionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ResourceAction(java.lang.String name, ResourceActionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Optimizer/resourceAction:ResourceAction", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ResourceAction(java.lang.String name, Output<java.lang.String> id, @Nullable ResourceActionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Optimizer/resourceAction:ResourceAction", name, state, makeResourceOptions(options, id), false);
    }

    private static ResourceActionArgs makeArgs(ResourceActionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ResourceActionArgs.Empty : args;
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
    public static ResourceAction get(java.lang.String name, Output<java.lang.String> id, @Nullable ResourceActionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ResourceAction(name, id, state, options);
    }
}
