// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.MediaServices.MediaWorkflowConfigurationArgs;
import com.pulumi.oci.MediaServices.inputs.MediaWorkflowConfigurationState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Media Workflow Configuration resource in Oracle Cloud Infrastructure Media Services service.
 * 
 * Creates a new MediaWorkflowConfiguration.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.MediaServices.MediaWorkflowConfiguration;
 * import com.pulumi.oci.MediaServices.MediaWorkflowConfigurationArgs;
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
 *         var testMediaWorkflowConfiguration = new MediaWorkflowConfiguration(&#34;testMediaWorkflowConfiguration&#34;, MediaWorkflowConfigurationArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.media_workflow_configuration_display_name())
 *             .parameters(var_.media_workflow_configuration_parameters())
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
 * MediaWorkflowConfigurations can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:MediaServices/mediaWorkflowConfiguration:MediaWorkflowConfiguration test_media_workflow_configuration &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:MediaServices/mediaWorkflowConfiguration:MediaWorkflowConfiguration")
public class MediaWorkflowConfiguration extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment Identifier.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier.
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
     * (Updatable) MediaWorkflowConfiguration identifier. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) MediaWorkflowConfiguration identifier. Avoid entering confidential information.
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
     * (Updatable) Reuseable parameter values encoded as a JSON; the top and second level JSON elements are objects. Each key of the top level object refers to a task key that is unqiue to the workflow, each of the second level objects&#39; keys refer to the name of a parameter that is unique to the task. taskKey &gt; parameterName &gt; parameterValue
     * 
     */
    @Export(name="parameters", type=String.class, parameters={})
    private Output<String> parameters;

    /**
     * @return (Updatable) Reuseable parameter values encoded as a JSON; the top and second level JSON elements are objects. Each key of the top level object refers to a task key that is unqiue to the workflow, each of the second level objects&#39; keys refer to the name of a parameter that is unique to the task. taskKey &gt; parameterName &gt; parameterValue
     * 
     */
    public Output<String> parameters() {
        return this.parameters;
    }
    /**
     * The current state of the MediaWorkflowConfiguration.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the MediaWorkflowConfiguration.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when the the MediaWorkflowConfiguration was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time when the the MediaWorkflowConfiguration was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the MediaWorkflowConfiguration was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time when the MediaWorkflowConfiguration was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MediaWorkflowConfiguration(String name) {
        this(name, MediaWorkflowConfigurationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MediaWorkflowConfiguration(String name, MediaWorkflowConfigurationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MediaWorkflowConfiguration(String name, MediaWorkflowConfigurationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/mediaWorkflowConfiguration:MediaWorkflowConfiguration", name, args == null ? MediaWorkflowConfigurationArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private MediaWorkflowConfiguration(String name, Output<String> id, @Nullable MediaWorkflowConfigurationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/mediaWorkflowConfiguration:MediaWorkflowConfiguration", name, state, makeResourceOptions(options, id));
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
    public static MediaWorkflowConfiguration get(String name, Output<String> id, @Nullable MediaWorkflowConfigurationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MediaWorkflowConfiguration(name, id, state, options);
    }
}