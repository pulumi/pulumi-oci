// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.LogAnalytics.LogAnalyticsLogGroupArgs;
import com.pulumi.oci.LogAnalytics.inputs.LogAnalyticsLogGroupState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Log Analytics Log Group resource in Oracle Cloud Infrastructure Log Analytics service.
 * 
 * Creates a new log group in the specified compartment with the input display name. You may also specify optional information such as description, defined tags, and free-form tags.
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
 * import com.pulumi.oci.LogAnalytics.LogAnalyticsLogGroup;
 * import com.pulumi.oci.LogAnalytics.LogAnalyticsLogGroupArgs;
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
 *         var testLogAnalyticsLogGroup = new LogAnalyticsLogGroup("testLogAnalyticsLogGroup", LogAnalyticsLogGroupArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(logAnalyticsLogGroupDisplayName)
 *             .namespace(logAnalyticsLogGroupNamespace)
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(logAnalyticsLogGroupDescription)
 *             .freeformTags(Map.of("bar-key", "value"))
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
 * LogAnalyticsLogGroups can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup test_log_analytics_log_group &#34;namespaces/{namespaceName}/logAnalyticsLogGroups/{logAnalyticsLogGroupId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup")
public class LogAnalyticsLogGroup extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description for this resource.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Description for this resource.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The Logging Analytics namespace used for the request.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }
    /**
     * The date and time the resource was created, in the format defined by RFC3339.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, in the format defined by RFC3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was last updated, in the format defined by RFC3339.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was last updated, in the format defined by RFC3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public LogAnalyticsLogGroup(java.lang.String name) {
        this(name, LogAnalyticsLogGroupArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public LogAnalyticsLogGroup(java.lang.String name, LogAnalyticsLogGroupArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public LogAnalyticsLogGroup(java.lang.String name, LogAnalyticsLogGroupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private LogAnalyticsLogGroup(java.lang.String name, Output<java.lang.String> id, @Nullable LogAnalyticsLogGroupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LogAnalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup", name, state, makeResourceOptions(options, id), false);
    }

    private static LogAnalyticsLogGroupArgs makeArgs(LogAnalyticsLogGroupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? LogAnalyticsLogGroupArgs.Empty : args;
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
    public static LogAnalyticsLogGroup get(java.lang.String name, Output<java.lang.String> id, @Nullable LogAnalyticsLogGroupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new LogAnalyticsLogGroup(name, id, state, options);
    }
}
