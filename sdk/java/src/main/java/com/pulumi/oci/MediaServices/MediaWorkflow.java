// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.MediaServices.MediaWorkflowArgs;
import com.pulumi.oci.MediaServices.inputs.MediaWorkflowState;
import com.pulumi.oci.MediaServices.outputs.MediaWorkflowLock;
import com.pulumi.oci.MediaServices.outputs.MediaWorkflowTask;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Media Workflow resource in Oracle Cloud Infrastructure Media Services service.
 * 
 * Creates a new MediaWorkflow.
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
 * import com.pulumi.oci.MediaServices.MediaWorkflow;
 * import com.pulumi.oci.MediaServices.MediaWorkflowArgs;
 * import com.pulumi.oci.MediaServices.inputs.MediaWorkflowLockArgs;
 * import com.pulumi.oci.MediaServices.inputs.MediaWorkflowTaskArgs;
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
 *         var testMediaWorkflow = new MediaWorkflow("testMediaWorkflow", MediaWorkflowArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(mediaWorkflowDisplayName)
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .locks(MediaWorkflowLockArgs.builder()
 *                 .compartmentId(compartmentId)
 *                 .type(mediaWorkflowLocksType)
 *                 .message(mediaWorkflowLocksMessage)
 *                 .relatedResourceId(testResource.id())
 *                 .timeCreated(mediaWorkflowLocksTimeCreated)
 *                 .build())
 *             .mediaWorkflowConfigurationIds(mediaWorkflowMediaWorkflowConfigurationIds)
 *             .parameters(mediaWorkflowParameters)
 *             .tasks(MediaWorkflowTaskArgs.builder()
 *                 .key(mediaWorkflowTasksKey)
 *                 .parameters(mediaWorkflowTasksParameters)
 *                 .type(mediaWorkflowTasksType)
 *                 .version(mediaWorkflowTasksVersion)
 *                 .enableParameterReference(mediaWorkflowTasksEnableParameterReference)
 *                 .enableWhenReferencedParameterEquals(mediaWorkflowTasksEnableWhenReferencedParameterEquals)
 *                 .prerequisites(mediaWorkflowTasksPrerequisites)
 *                 .build())
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
 * MediaWorkflows can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:MediaServices/mediaWorkflow:MediaWorkflow test_media_workflow &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:MediaServices/mediaWorkflow:MediaWorkflow")
public class MediaWorkflow extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment Identifier.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
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
     * (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
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
    @Export(name="isLockOverride", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isLockOverride;

    public Output<Boolean> isLockOverride() {
        return this.isLockOverride;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecyleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecyleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecyleDetails() {
        return this.lifecyleDetails;
    }
    /**
     * Locks associated with this resource.
     * 
     */
    @Export(name="locks", refs={List.class,MediaWorkflowLock.class}, tree="[0,1]")
    private Output<List<MediaWorkflowLock>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Output<List<MediaWorkflowLock>> locks() {
        return this.locks;
    }
    /**
     * (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
     * 
     */
    @Export(name="mediaWorkflowConfigurationIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> mediaWorkflowConfigurationIds;

    /**
     * @return (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
     * 
     */
    public Output<List<String>> mediaWorkflowConfigurationIds() {
        return this.mediaWorkflowConfigurationIds;
    }
    /**
     * (Updatable) JSON object representing named parameters and their default values that can be referenced throughout this workflow. The values declared here can be overridden by the MediaWorkflowConfigurations or parameters supplied when creating MediaWorkflowJobs from this MediaWorkflow.
     * 
     */
    @Export(name="parameters", refs={String.class}, tree="[0]")
    private Output<String> parameters;

    /**
     * @return (Updatable) JSON object representing named parameters and their default values that can be referenced throughout this workflow. The values declared here can be overridden by the MediaWorkflowConfigurations or parameters supplied when creating MediaWorkflowJobs from this MediaWorkflow.
     * 
     */
    public Output<String> parameters() {
        return this.parameters;
    }
    /**
     * The current state of the MediaWorkflow.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the MediaWorkflow.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
     * 
     */
    @Export(name="tasks", refs={List.class,MediaWorkflowTask.class}, tree="[0,1]")
    private Output<List<MediaWorkflowTask>> tasks;

    /**
     * @return (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
     * 
     */
    public Output<List<MediaWorkflowTask>> tasks() {
        return this.tasks;
    }
    /**
     * The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The version of the MediaWorkflow.
     * 
     */
    @Export(name="version", refs={String.class}, tree="[0]")
    private Output<String> version;

    /**
     * @return The version of the MediaWorkflow.
     * 
     */
    public Output<String> version() {
        return this.version;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MediaWorkflow(java.lang.String name) {
        this(name, MediaWorkflowArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MediaWorkflow(java.lang.String name, MediaWorkflowArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MediaWorkflow(java.lang.String name, MediaWorkflowArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/mediaWorkflow:MediaWorkflow", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private MediaWorkflow(java.lang.String name, Output<java.lang.String> id, @Nullable MediaWorkflowState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/mediaWorkflow:MediaWorkflow", name, state, makeResourceOptions(options, id), false);
    }

    private static MediaWorkflowArgs makeArgs(MediaWorkflowArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? MediaWorkflowArgs.Empty : args;
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
    public static MediaWorkflow get(java.lang.String name, Output<java.lang.String> id, @Nullable MediaWorkflowState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MediaWorkflow(name, id, state, options);
    }
}
