// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CloudGuard.ManagedListArgs;
import com.pulumi.oci.CloudGuard.inputs.ManagedListState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Managed List resource in Oracle Cloud Infrastructure Cloud Guard service.
 * 
 * Creates a new ManagedList.
 * 
 * ## Import
 * 
 * ManagedLists can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:CloudGuard/managedList:ManagedList test_managed_list &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CloudGuard/managedList:ManagedList")
public class ManagedList extends com.pulumi.resources.CustomResource {
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
     * (Updatable) Managed list description.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Managed list description.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Managed list display name.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Managed list display name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * provider of the feed
     * 
     */
    @Export(name="feedProvider", type=String.class, parameters={})
    private Output<String> feedProvider;

    /**
     * @return provider of the feed
     * 
     */
    public Output<String> feedProvider() {
        return this.feedProvider;
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
     * If this list is editable or not
     * 
     */
    @Export(name="isEditable", type=Boolean.class, parameters={})
    private Output<Boolean> isEditable;

    /**
     * @return If this list is editable or not
     * 
     */
    public Output<Boolean> isEditable() {
        return this.isEditable;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecyleDetails", type=String.class, parameters={})
    private Output<String> lifecyleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecyleDetails() {
        return this.lifecyleDetails;
    }
    /**
     * (Updatable) List of ManagedListItem
     * 
     */
    @Export(name="listItems", type=List.class, parameters={String.class})
    private Output<List<String>> listItems;

    /**
     * @return (Updatable) List of ManagedListItem
     * 
     */
    public Output<List<String>> listItems() {
        return this.listItems;
    }
    /**
     * type of the list
     * 
     */
    @Export(name="listType", type=String.class, parameters={})
    private Output<String> listType;

    /**
     * @return type of the list
     * 
     */
    public Output<String> listType() {
        return this.listType;
    }
    /**
     * OCID of the Source ManagedList
     * 
     */
    @Export(name="sourceManagedListId", type=String.class, parameters={})
    private Output<String> sourceManagedListId;

    /**
     * @return OCID of the Source ManagedList
     * 
     */
    public Output<String> sourceManagedListId() {
        return this.sourceManagedListId;
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
     * The date and time the managed list was created. Format defined by RFC3339.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the managed list was created. Format defined by RFC3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the managed list was updated. Format defined by RFC3339.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the managed list was updated. Format defined by RFC3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagedList(String name) {
        this(name, ManagedListArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagedList(String name, ManagedListArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagedList(String name, ManagedListArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudGuard/managedList:ManagedList", name, args == null ? ManagedListArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ManagedList(String name, Output<String> id, @Nullable ManagedListState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudGuard/managedList:ManagedList", name, state, makeResourceOptions(options, id));
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
    public static ManagedList get(String name, Output<String> id, @Nullable ManagedListState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagedList(name, id, state, options);
    }
}