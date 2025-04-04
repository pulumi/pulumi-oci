// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataScience.PipelineArgs;
import com.pulumi.oci.DataScience.inputs.PipelineState;
import com.pulumi.oci.DataScience.outputs.PipelineConfigurationDetails;
import com.pulumi.oci.DataScience.outputs.PipelineInfrastructureConfigurationDetails;
import com.pulumi.oci.DataScience.outputs.PipelineLogConfigurationDetails;
import com.pulumi.oci.DataScience.outputs.PipelineStepArtifact;
import com.pulumi.oci.DataScience.outputs.PipelineStepDetail;
import com.pulumi.oci.DataScience.outputs.PipelineStorageMountConfigurationDetailsList;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Pipeline resource in Oracle Cloud Infrastructure Data Science service.
 * 
 * Creates a new Pipeline.
 * 
 * ## Import
 * 
 * Pipelines can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DataScience/pipeline:Pipeline test_pipeline &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataScience/pipeline:Pipeline")
public class Pipeline extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The configuration details of a pipeline.
     * 
     */
    @Export(name="configurationDetails", refs={PipelineConfigurationDetails.class}, tree="[0]")
    private Output<PipelineConfigurationDetails> configurationDetails;

    /**
     * @return (Updatable) The configuration details of a pipeline.
     * 
     */
    public Output<PipelineConfigurationDetails> configurationDetails() {
        return this.configurationDetails;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
     * 
     */
    @Export(name="createdBy", refs={String.class}, tree="[0]")
    private Output<String> createdBy;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
     * 
     */
    public Output<String> createdBy() {
        return this.createdBy;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    @Export(name="deleteRelatedPipelineRuns", refs={Boolean.class}, tree="[0]")
    private Output</* @Nullable */ Boolean> deleteRelatedPipelineRuns;

    public Output<Optional<Boolean>> deleteRelatedPipelineRuns() {
        return Codegen.optional(this.deleteRelatedPipelineRuns);
    }
    /**
     * (Updatable) A short description of the pipeline.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) A short description of the pipeline.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly display name for the resource.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The infrastructure configuration details of a pipeline or a step.
     * 
     */
    @Export(name="infrastructureConfigurationDetails", refs={PipelineInfrastructureConfigurationDetails.class}, tree="[0]")
    private Output<PipelineInfrastructureConfigurationDetails> infrastructureConfigurationDetails;

    /**
     * @return (Updatable) The infrastructure configuration details of a pipeline or a step.
     * 
     */
    public Output<PipelineInfrastructureConfigurationDetails> infrastructureConfigurationDetails() {
        return this.infrastructureConfigurationDetails;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in &#39;Failed&#39; state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in &#39;Failed&#39; state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) The pipeline log configuration details.
     * 
     */
    @Export(name="logConfigurationDetails", refs={PipelineLogConfigurationDetails.class}, tree="[0]")
    private Output<PipelineLogConfigurationDetails> logConfigurationDetails;

    /**
     * @return (Updatable) The pipeline log configuration details.
     * 
     */
    public Output<PipelineLogConfigurationDetails> logConfigurationDetails() {
        return this.logConfigurationDetails;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     * 
     */
    @Export(name="projectId", refs={String.class}, tree="[0]")
    private Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * The current state of the pipeline.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the pipeline.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    @Export(name="stepArtifacts", refs={List.class,PipelineStepArtifact.class}, tree="[0,1]")
    private Output<List<PipelineStepArtifact>> stepArtifacts;

    public Output<List<PipelineStepArtifact>> stepArtifacts() {
        return this.stepArtifacts;
    }
    /**
     * (Updatable) Array of step details for each step.
     * 
     */
    @Export(name="stepDetails", refs={List.class,PipelineStepDetail.class}, tree="[0,1]")
    private Output<List<PipelineStepDetail>> stepDetails;

    /**
     * @return (Updatable) Array of step details for each step.
     * 
     */
    public Output<List<PipelineStepDetail>> stepDetails() {
        return this.stepDetails;
    }
    /**
     * (Updatable) The storage mount details to mount to the instance running the pipeline step.
     * 
     */
    @Export(name="storageMountConfigurationDetailsLists", refs={List.class,PipelineStorageMountConfigurationDetailsList.class}, tree="[0,1]")
    private Output<List<PipelineStorageMountConfigurationDetailsList>> storageMountConfigurationDetailsLists;

    /**
     * @return (Updatable) The storage mount details to mount to the instance running the pipeline step.
     * 
     */
    public Output<List<PipelineStorageMountConfigurationDetailsList>> storageMountConfigurationDetailsLists() {
        return this.storageMountConfigurationDetailsLists;
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
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Pipeline(java.lang.String name) {
        this(name, PipelineArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Pipeline(java.lang.String name, PipelineArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Pipeline(java.lang.String name, PipelineArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataScience/pipeline:Pipeline", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Pipeline(java.lang.String name, Output<java.lang.String> id, @Nullable PipelineState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataScience/pipeline:Pipeline", name, state, makeResourceOptions(options, id), false);
    }

    private static PipelineArgs makeArgs(PipelineArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? PipelineArgs.Empty : args;
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
    public static Pipeline get(java.lang.String name, Output<java.lang.String> id, @Nullable PipelineState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Pipeline(name, id, state, options);
    }
}
