// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.PipelineConfigurationDetailsArgs;
import com.pulumi.oci.DataScience.inputs.PipelineInfrastructureConfigurationDetailsArgs;
import com.pulumi.oci.DataScience.inputs.PipelineLogConfigurationDetailsArgs;
import com.pulumi.oci.DataScience.inputs.PipelineStepArtifactArgs;
import com.pulumi.oci.DataScience.inputs.PipelineStepDetailArgs;
import com.pulumi.oci.DataScience.inputs.PipelineStorageMountConfigurationDetailsListArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PipelineState extends com.pulumi.resources.ResourceArgs {

    public static final PipelineState Empty = new PipelineState();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) The configuration details of a pipeline.
     * 
     */
    @Import(name="configurationDetails")
    private @Nullable Output<PipelineConfigurationDetailsArgs> configurationDetails;

    /**
     * @return (Updatable) The configuration details of a pipeline.
     * 
     */
    public Optional<Output<PipelineConfigurationDetailsArgs>> configurationDetails() {
        return Optional.ofNullable(this.configurationDetails);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
     * 
     */
    @Import(name="createdBy")
    private @Nullable Output<String> createdBy;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
     * 
     */
    public Optional<Output<String>> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    @Import(name="deleteRelatedPipelineRuns")
    private @Nullable Output<Boolean> deleteRelatedPipelineRuns;

    public Optional<Output<Boolean>> deleteRelatedPipelineRuns() {
        return Optional.ofNullable(this.deleteRelatedPipelineRuns);
    }

    /**
     * (Updatable) A short description of the pipeline.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A short description of the pipeline.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly display name for the resource.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The infrastructure configuration details of a pipeline or a step.
     * 
     */
    @Import(name="infrastructureConfigurationDetails")
    private @Nullable Output<PipelineInfrastructureConfigurationDetailsArgs> infrastructureConfigurationDetails;

    /**
     * @return (Updatable) The infrastructure configuration details of a pipeline or a step.
     * 
     */
    public Optional<Output<PipelineInfrastructureConfigurationDetailsArgs>> infrastructureConfigurationDetails() {
        return Optional.ofNullable(this.infrastructureConfigurationDetails);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in &#39;Failed&#39; state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in &#39;Failed&#39; state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) The pipeline log configuration details.
     * 
     */
    @Import(name="logConfigurationDetails")
    private @Nullable Output<PipelineLogConfigurationDetailsArgs> logConfigurationDetails;

    /**
     * @return (Updatable) The pipeline log configuration details.
     * 
     */
    public Optional<Output<PipelineLogConfigurationDetailsArgs>> logConfigurationDetails() {
        return Optional.ofNullable(this.logConfigurationDetails);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     * 
     */
    @Import(name="projectId")
    private @Nullable Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     * 
     */
    public Optional<Output<String>> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * The current state of the pipeline.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the pipeline.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    @Import(name="stepArtifacts")
    private @Nullable Output<List<PipelineStepArtifactArgs>> stepArtifacts;

    public Optional<Output<List<PipelineStepArtifactArgs>>> stepArtifacts() {
        return Optional.ofNullable(this.stepArtifacts);
    }

    /**
     * (Updatable) Array of step details for each step.
     * 
     */
    @Import(name="stepDetails")
    private @Nullable Output<List<PipelineStepDetailArgs>> stepDetails;

    /**
     * @return (Updatable) Array of step details for each step.
     * 
     */
    public Optional<Output<List<PipelineStepDetailArgs>>> stepDetails() {
        return Optional.ofNullable(this.stepDetails);
    }

    /**
     * (Updatable) The storage mount details to mount to the instance running the pipeline step.
     * 
     */
    @Import(name="storageMountConfigurationDetailsLists")
    private @Nullable Output<List<PipelineStorageMountConfigurationDetailsListArgs>> storageMountConfigurationDetailsLists;

    /**
     * @return (Updatable) The storage mount details to mount to the instance running the pipeline step.
     * 
     */
    public Optional<Output<List<PipelineStorageMountConfigurationDetailsListArgs>>> storageMountConfigurationDetailsLists() {
        return Optional.ofNullable(this.storageMountConfigurationDetailsLists);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private PipelineState() {}

    private PipelineState(PipelineState $) {
        this.compartmentId = $.compartmentId;
        this.configurationDetails = $.configurationDetails;
        this.createdBy = $.createdBy;
        this.definedTags = $.definedTags;
        this.deleteRelatedPipelineRuns = $.deleteRelatedPipelineRuns;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.infrastructureConfigurationDetails = $.infrastructureConfigurationDetails;
        this.lifecycleDetails = $.lifecycleDetails;
        this.logConfigurationDetails = $.logConfigurationDetails;
        this.projectId = $.projectId;
        this.state = $.state;
        this.stepArtifacts = $.stepArtifacts;
        this.stepDetails = $.stepDetails;
        this.storageMountConfigurationDetailsLists = $.storageMountConfigurationDetailsLists;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PipelineState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PipelineState $;

        public Builder() {
            $ = new PipelineState();
        }

        public Builder(PipelineState defaults) {
            $ = new PipelineState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param configurationDetails (Updatable) The configuration details of a pipeline.
         * 
         * @return builder
         * 
         */
        public Builder configurationDetails(@Nullable Output<PipelineConfigurationDetailsArgs> configurationDetails) {
            $.configurationDetails = configurationDetails;
            return this;
        }

        /**
         * @param configurationDetails (Updatable) The configuration details of a pipeline.
         * 
         * @return builder
         * 
         */
        public Builder configurationDetails(PipelineConfigurationDetailsArgs configurationDetails) {
            return configurationDetails(Output.of(configurationDetails));
        }

        /**
         * @param createdBy The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable Output<String> createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param createdBy The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(String createdBy) {
            return createdBy(Output.of(createdBy));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        public Builder deleteRelatedPipelineRuns(@Nullable Output<Boolean> deleteRelatedPipelineRuns) {
            $.deleteRelatedPipelineRuns = deleteRelatedPipelineRuns;
            return this;
        }

        public Builder deleteRelatedPipelineRuns(Boolean deleteRelatedPipelineRuns) {
            return deleteRelatedPipelineRuns(Output.of(deleteRelatedPipelineRuns));
        }

        /**
         * @param description (Updatable) A short description of the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A short description of the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param infrastructureConfigurationDetails (Updatable) The infrastructure configuration details of a pipeline or a step.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureConfigurationDetails(@Nullable Output<PipelineInfrastructureConfigurationDetailsArgs> infrastructureConfigurationDetails) {
            $.infrastructureConfigurationDetails = infrastructureConfigurationDetails;
            return this;
        }

        /**
         * @param infrastructureConfigurationDetails (Updatable) The infrastructure configuration details of a pipeline or a step.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureConfigurationDetails(PipelineInfrastructureConfigurationDetailsArgs infrastructureConfigurationDetails) {
            return infrastructureConfigurationDetails(Output.of(infrastructureConfigurationDetails));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in &#39;Failed&#39; state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in &#39;Failed&#39; state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param logConfigurationDetails (Updatable) The pipeline log configuration details.
         * 
         * @return builder
         * 
         */
        public Builder logConfigurationDetails(@Nullable Output<PipelineLogConfigurationDetailsArgs> logConfigurationDetails) {
            $.logConfigurationDetails = logConfigurationDetails;
            return this;
        }

        /**
         * @param logConfigurationDetails (Updatable) The pipeline log configuration details.
         * 
         * @return builder
         * 
         */
        public Builder logConfigurationDetails(PipelineLogConfigurationDetailsArgs logConfigurationDetails) {
            return logConfigurationDetails(Output.of(logConfigurationDetails));
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param state The current state of the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public Builder stepArtifacts(@Nullable Output<List<PipelineStepArtifactArgs>> stepArtifacts) {
            $.stepArtifacts = stepArtifacts;
            return this;
        }

        public Builder stepArtifacts(List<PipelineStepArtifactArgs> stepArtifacts) {
            return stepArtifacts(Output.of(stepArtifacts));
        }

        public Builder stepArtifacts(PipelineStepArtifactArgs... stepArtifacts) {
            return stepArtifacts(List.of(stepArtifacts));
        }

        /**
         * @param stepDetails (Updatable) Array of step details for each step.
         * 
         * @return builder
         * 
         */
        public Builder stepDetails(@Nullable Output<List<PipelineStepDetailArgs>> stepDetails) {
            $.stepDetails = stepDetails;
            return this;
        }

        /**
         * @param stepDetails (Updatable) Array of step details for each step.
         * 
         * @return builder
         * 
         */
        public Builder stepDetails(List<PipelineStepDetailArgs> stepDetails) {
            return stepDetails(Output.of(stepDetails));
        }

        /**
         * @param stepDetails (Updatable) Array of step details for each step.
         * 
         * @return builder
         * 
         */
        public Builder stepDetails(PipelineStepDetailArgs... stepDetails) {
            return stepDetails(List.of(stepDetails));
        }

        /**
         * @param storageMountConfigurationDetailsLists (Updatable) The storage mount details to mount to the instance running the pipeline step.
         * 
         * @return builder
         * 
         */
        public Builder storageMountConfigurationDetailsLists(@Nullable Output<List<PipelineStorageMountConfigurationDetailsListArgs>> storageMountConfigurationDetailsLists) {
            $.storageMountConfigurationDetailsLists = storageMountConfigurationDetailsLists;
            return this;
        }

        /**
         * @param storageMountConfigurationDetailsLists (Updatable) The storage mount details to mount to the instance running the pipeline step.
         * 
         * @return builder
         * 
         */
        public Builder storageMountConfigurationDetailsLists(List<PipelineStorageMountConfigurationDetailsListArgs> storageMountConfigurationDetailsLists) {
            return storageMountConfigurationDetailsLists(Output.of(storageMountConfigurationDetailsLists));
        }

        /**
         * @param storageMountConfigurationDetailsLists (Updatable) The storage mount details to mount to the instance running the pipeline step.
         * 
         * @return builder
         * 
         */
        public Builder storageMountConfigurationDetailsLists(PipelineStorageMountConfigurationDetailsListArgs... storageMountConfigurationDetailsLists) {
            return storageMountConfigurationDetailsLists(List.of(storageMountConfigurationDetailsLists));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public PipelineState build() {
            return $;
        }
    }

}
