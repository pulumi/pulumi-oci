// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DevOps.TriggerArgs;
import com.pulumi.oci.DevOps.inputs.TriggerState;
import com.pulumi.oci.DevOps.outputs.TriggerAction;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Trigger resource in Oracle Cloud Infrastructure Devops service.
 * 
 * Creates a new trigger.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DevOps.Trigger;
 * import com.pulumi.oci.DevOps.TriggerArgs;
 * import com.pulumi.oci.DevOps.inputs.TriggerActionArgs;
 * import com.pulumi.oci.DevOps.inputs.TriggerActionFilterArgs;
 * import com.pulumi.oci.DevOps.inputs.TriggerActionFilterIncludeArgs;
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
 *         var testTrigger = new Trigger(&#34;testTrigger&#34;, TriggerArgs.builder()        
 *             .actions(TriggerActionArgs.builder()
 *                 .buildPipelineId(oci_devops_build_pipeline.test_build_pipeline().id())
 *                 .type(var_.trigger_actions_type())
 *                 .filter(TriggerActionFilterArgs.builder()
 *                     .triggerSource(var_.trigger_actions_filter_trigger_source())
 *                     .events(var_.trigger_actions_filter_events())
 *                     .include(TriggerActionFilterIncludeArgs.builder()
 *                         .baseRef(var_.trigger_actions_filter_include_base_ref())
 *                         .headRef(var_.trigger_actions_filter_include_head_ref())
 *                         .build())
 *                     .build())
 *                 .build())
 *             .projectId(oci_devops_project.test_project().id())
 *             .triggerSource(var_.trigger_trigger_source())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .description(var_.trigger_description())
 *             .displayName(var_.trigger_display_name())
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .repositoryId(oci_artifacts_repository.test_repository().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Triggers can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DevOps/trigger:Trigger test_trigger &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DevOps/trigger:Trigger")
public class Trigger extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The list of actions that are to be performed for this trigger.
     * 
     */
    @Export(name="actions", type=List.class, parameters={TriggerAction.class})
    private Output<List<TriggerAction>> actions;

    /**
     * @return (Updatable) The list of actions that are to be performed for this trigger.
     * 
     */
    public Output<List<TriggerAction>> actions() {
        return this.actions;
    }
    /**
     * The OCID of the compartment that contains the trigger.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains the trigger.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    @Export(name="connectionId", type=String.class, parameters={})
    private Output<String> connectionId;

    public Output<String> connectionId() {
        return this.connectionId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Optional description about the trigger.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Optional description about the trigger.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Trigger display name. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Trigger display name. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The OCID of the DevOps project to which the trigger belongs to.
     * 
     */
    @Export(name="projectId", type=String.class, parameters={})
    private Output<String> projectId;

    /**
     * @return The OCID of the DevOps project to which the trigger belongs to.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * (Updatable) The OCID of the DevOps code repository.
     * 
     */
    @Export(name="repositoryId", type=String.class, parameters={})
    private Output<String> repositoryId;

    /**
     * @return (Updatable) The OCID of the DevOps code repository.
     * 
     */
    public Output<String> repositoryId() {
        return this.repositoryId;
    }
    /**
     * The current state of the trigger.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the trigger.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the trigger was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time the trigger was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the trigger was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the trigger was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
     * 
     */
    @Export(name="triggerSource", type=String.class, parameters={})
    private Output<String> triggerSource;

    /**
     * @return (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
     * 
     */
    public Output<String> triggerSource() {
        return this.triggerSource;
    }
    /**
     * The endpoint that listens to trigger events.
     * 
     */
    @Export(name="triggerUrl", type=String.class, parameters={})
    private Output<String> triggerUrl;

    /**
     * @return The endpoint that listens to trigger events.
     * 
     */
    public Output<String> triggerUrl() {
        return this.triggerUrl;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Trigger(String name) {
        this(name, TriggerArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Trigger(String name, TriggerArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Trigger(String name, TriggerArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/trigger:Trigger", name, args == null ? TriggerArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Trigger(String name, Output<String> id, @Nullable TriggerState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/trigger:Trigger", name, state, makeResourceOptions(options, id));
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
    public static Trigger get(String name, Output<String> id, @Nullable TriggerState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Trigger(name, id, state, options);
    }
}