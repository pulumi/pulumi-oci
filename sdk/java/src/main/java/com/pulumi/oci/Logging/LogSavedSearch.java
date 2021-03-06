// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Logging.LogSavedSearchArgs;
import com.pulumi.oci.Logging.inputs.LogSavedSearchState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Log Saved Search resource in Oracle Cloud Infrastructure Logging service.
 * 
 * Creates a new LogSavedSearch.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * LogSavedSearches can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Logging/logSavedSearch:LogSavedSearch test_log_saved_search &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Logging/logSavedSearch:LogSavedSearch")
public class LogSavedSearch extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment that the resource belongs to.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that the resource belongs to.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description for this resource.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Description for this resource.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) The search query that is saved.
     * 
     */
    @Export(name="query", type=String.class, parameters={})
    private Output<String> query;

    /**
     * @return (Updatable) The search query that is saved.
     * 
     */
    public Output<String> query() {
        return this.query;
    }
    /**
     * The state of the LogSavedSearch
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The state of the LogSavedSearch
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Time the resource was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return Time the resource was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * Time the resource was last modified.
     * 
     */
    @Export(name="timeLastModified", type=String.class, parameters={})
    private Output<String> timeLastModified;

    /**
     * @return Time the resource was last modified.
     * 
     */
    public Output<String> timeLastModified() {
        return this.timeLastModified;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public LogSavedSearch(String name) {
        this(name, LogSavedSearchArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public LogSavedSearch(String name, LogSavedSearchArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public LogSavedSearch(String name, LogSavedSearchArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Logging/logSavedSearch:LogSavedSearch", name, args == null ? LogSavedSearchArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private LogSavedSearch(String name, Output<String> id, @Nullable LogSavedSearchState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Logging/logSavedSearch:LogSavedSearch", name, state, makeResourceOptions(options, id));
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
    public static LogSavedSearch get(String name, Output<String> id, @Nullable LogSavedSearchState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new LogSavedSearch(name, id, state, options);
    }
}
