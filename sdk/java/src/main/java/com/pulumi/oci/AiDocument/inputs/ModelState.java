// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.AiDocument.inputs.ModelComponentModelArgs;
import com.pulumi.oci.AiDocument.inputs.ModelMetricArgs;
import com.pulumi.oci.AiDocument.inputs.ModelTestingDatasetArgs;
import com.pulumi.oci.AiDocument.inputs.ModelTrainingDatasetArgs;
import com.pulumi.oci.AiDocument.inputs.ModelValidationDatasetArgs;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelState extends com.pulumi.resources.ResourceArgs {

    public static final ModelState Empty = new ModelState();

    /**
     * (Updatable) The compartment identifier.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The compartment identifier.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) list of active custom Key Value models that need to be composed.
     * 
     */
    @Import(name="componentModels")
    private @Nullable Output<List<ModelComponentModelArgs>> componentModels;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) list of active custom Key Value models that need to be composed.
     * 
     */
    public Optional<Output<List<ModelComponentModelArgs>>> componentModels() {
        return Optional.ofNullable(this.componentModels);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) An optional description of the model.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) An optional description of the model.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A human-friendly name for the model, which can be changed.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A human-friendly name for the model, which can be changed.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Set to true when the model is created by using multiple key value extraction models.
     * 
     */
    @Import(name="isComposedModel")
    private @Nullable Output<Boolean> isComposedModel;

    /**
     * @return Set to true when the model is created by using multiple key value extraction models.
     * 
     */
    public Optional<Output<Boolean>> isComposedModel() {
        return Optional.ofNullable(this.isComposedModel);
    }

    /**
     * Set to true when experimenting with a new model type or dataset, so the model training is quick, with a predefined low number of passes through the training data.
     * 
     */
    @Import(name="isQuickMode")
    private @Nullable Output<Boolean> isQuickMode;

    /**
     * @return Set to true when experimenting with a new model type or dataset, so the model training is quick, with a predefined low number of passes through the training data.
     * 
     */
    public Optional<Output<Boolean>> isQuickMode() {
        return Optional.ofNullable(this.isQuickMode);
    }

    /**
     * The collection of labels used to train the custom model.
     * 
     */
    @Import(name="labels")
    private @Nullable Output<List<String>> labels;

    /**
     * @return The collection of labels used to train the custom model.
     * 
     */
    public Optional<Output<List<String>>> labels() {
        return Optional.ofNullable(this.labels);
    }

    /**
     * A message describing the current state in more detail, that can provide actionable information if training failed.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail, that can provide actionable information if training failed.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The maximum model training time in hours, expressed as a decimal fraction.
     * 
     */
    @Import(name="maxTrainingTimeInHours")
    private @Nullable Output<Double> maxTrainingTimeInHours;

    /**
     * @return The maximum model training time in hours, expressed as a decimal fraction.
     * 
     */
    public Optional<Output<Double>> maxTrainingTimeInHours() {
        return Optional.ofNullable(this.maxTrainingTimeInHours);
    }

    /**
     * Trained Model Metrics.
     * 
     */
    @Import(name="metrics")
    private @Nullable Output<List<ModelMetricArgs>> metrics;

    /**
     * @return Trained Model Metrics.
     * 
     */
    public Optional<Output<List<ModelMetricArgs>>> metrics() {
        return Optional.ofNullable(this.metrics);
    }

    @Import(name="modelId")
    private @Nullable Output<String> modelId;

    public Optional<Output<String>> modelId() {
        return Optional.ofNullable(this.modelId);
    }

    /**
     * The type of the Document model.
     * 
     */
    @Import(name="modelType")
    private @Nullable Output<String> modelType;

    /**
     * @return The type of the Document model.
     * 
     */
    public Optional<Output<String>> modelType() {
        return Optional.ofNullable(this.modelType);
    }

    /**
     * The model version
     * 
     */
    @Import(name="modelVersion")
    private @Nullable Output<String> modelVersion;

    /**
     * @return The model version
     * 
     */
    public Optional<Output<String>> modelVersion() {
        return Optional.ofNullable(this.modelVersion);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
     * 
     */
    @Import(name="projectId")
    private @Nullable Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
     * 
     */
    public Optional<Output<String>> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * The current state of the model.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the model.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{&#34;orcl-cloud&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{&#34;orcl-cloud&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The tenancy id of the model.
     * 
     */
    @Import(name="tenancyId")
    private @Nullable Output<String> tenancyId;

    /**
     * @return The tenancy id of the model.
     * 
     */
    public Optional<Output<String>> tenancyId() {
        return Optional.ofNullable(this.tenancyId);
    }

    /**
     * The base entity which is the input for creating and training a model.
     * 
     */
    @Import(name="testingDataset")
    private @Nullable Output<ModelTestingDatasetArgs> testingDataset;

    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    public Optional<Output<ModelTestingDatasetArgs>> testingDataset() {
        return Optional.ofNullable(this.testingDataset);
    }

    /**
     * When the model was created, as an RFC3339 datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return When the model was created, as an RFC3339 datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * When the model was updated, as an RFC3339 datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return When the model was updated, as an RFC3339 datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The total hours actually used for model training.
     * 
     */
    @Import(name="trainedTimeInHours")
    private @Nullable Output<Double> trainedTimeInHours;

    /**
     * @return The total hours actually used for model training.
     * 
     */
    public Optional<Output<Double>> trainedTimeInHours() {
        return Optional.ofNullable(this.trainedTimeInHours);
    }

    /**
     * The base entity which is the input for creating and training a model.
     * 
     */
    @Import(name="trainingDataset")
    private @Nullable Output<ModelTrainingDatasetArgs> trainingDataset;

    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    public Optional<Output<ModelTrainingDatasetArgs>> trainingDataset() {
        return Optional.ofNullable(this.trainingDataset);
    }

    /**
     * The base entity which is the input for creating and training a model.
     * 
     */
    @Import(name="validationDataset")
    private @Nullable Output<ModelValidationDatasetArgs> validationDataset;

    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    public Optional<Output<ModelValidationDatasetArgs>> validationDataset() {
        return Optional.ofNullable(this.validationDataset);
    }

    private ModelState() {}

    private ModelState(ModelState $) {
        this.compartmentId = $.compartmentId;
        this.componentModels = $.componentModels;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isComposedModel = $.isComposedModel;
        this.isQuickMode = $.isQuickMode;
        this.labels = $.labels;
        this.lifecycleDetails = $.lifecycleDetails;
        this.maxTrainingTimeInHours = $.maxTrainingTimeInHours;
        this.metrics = $.metrics;
        this.modelId = $.modelId;
        this.modelType = $.modelType;
        this.modelVersion = $.modelVersion;
        this.projectId = $.projectId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.tenancyId = $.tenancyId;
        this.testingDataset = $.testingDataset;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.trainedTimeInHours = $.trainedTimeInHours;
        this.trainingDataset = $.trainingDataset;
        this.validationDataset = $.validationDataset;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelState $;

        public Builder() {
            $ = new ModelState();
        }

        public Builder(ModelState defaults) {
            $ = new ModelState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param componentModels The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) list of active custom Key Value models that need to be composed.
         * 
         * @return builder
         * 
         */
        public Builder componentModels(@Nullable Output<List<ModelComponentModelArgs>> componentModels) {
            $.componentModels = componentModels;
            return this;
        }

        /**
         * @param componentModels The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) list of active custom Key Value models that need to be composed.
         * 
         * @return builder
         * 
         */
        public Builder componentModels(List<ModelComponentModelArgs> componentModels) {
            return componentModels(Output.of(componentModels));
        }

        /**
         * @param componentModels The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) list of active custom Key Value models that need to be composed.
         * 
         * @return builder
         * 
         */
        public Builder componentModels(ModelComponentModelArgs... componentModels) {
            return componentModels(List.of(componentModels));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) An optional description of the model.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) An optional description of the model.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A human-friendly name for the model, which can be changed.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A human-friendly name for the model, which can be changed.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isComposedModel Set to true when the model is created by using multiple key value extraction models.
         * 
         * @return builder
         * 
         */
        public Builder isComposedModel(@Nullable Output<Boolean> isComposedModel) {
            $.isComposedModel = isComposedModel;
            return this;
        }

        /**
         * @param isComposedModel Set to true when the model is created by using multiple key value extraction models.
         * 
         * @return builder
         * 
         */
        public Builder isComposedModel(Boolean isComposedModel) {
            return isComposedModel(Output.of(isComposedModel));
        }

        /**
         * @param isQuickMode Set to true when experimenting with a new model type or dataset, so the model training is quick, with a predefined low number of passes through the training data.
         * 
         * @return builder
         * 
         */
        public Builder isQuickMode(@Nullable Output<Boolean> isQuickMode) {
            $.isQuickMode = isQuickMode;
            return this;
        }

        /**
         * @param isQuickMode Set to true when experimenting with a new model type or dataset, so the model training is quick, with a predefined low number of passes through the training data.
         * 
         * @return builder
         * 
         */
        public Builder isQuickMode(Boolean isQuickMode) {
            return isQuickMode(Output.of(isQuickMode));
        }

        /**
         * @param labels The collection of labels used to train the custom model.
         * 
         * @return builder
         * 
         */
        public Builder labels(@Nullable Output<List<String>> labels) {
            $.labels = labels;
            return this;
        }

        /**
         * @param labels The collection of labels used to train the custom model.
         * 
         * @return builder
         * 
         */
        public Builder labels(List<String> labels) {
            return labels(Output.of(labels));
        }

        /**
         * @param labels The collection of labels used to train the custom model.
         * 
         * @return builder
         * 
         */
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail, that can provide actionable information if training failed.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail, that can provide actionable information if training failed.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param maxTrainingTimeInHours The maximum model training time in hours, expressed as a decimal fraction.
         * 
         * @return builder
         * 
         */
        public Builder maxTrainingTimeInHours(@Nullable Output<Double> maxTrainingTimeInHours) {
            $.maxTrainingTimeInHours = maxTrainingTimeInHours;
            return this;
        }

        /**
         * @param maxTrainingTimeInHours The maximum model training time in hours, expressed as a decimal fraction.
         * 
         * @return builder
         * 
         */
        public Builder maxTrainingTimeInHours(Double maxTrainingTimeInHours) {
            return maxTrainingTimeInHours(Output.of(maxTrainingTimeInHours));
        }

        /**
         * @param metrics Trained Model Metrics.
         * 
         * @return builder
         * 
         */
        public Builder metrics(@Nullable Output<List<ModelMetricArgs>> metrics) {
            $.metrics = metrics;
            return this;
        }

        /**
         * @param metrics Trained Model Metrics.
         * 
         * @return builder
         * 
         */
        public Builder metrics(List<ModelMetricArgs> metrics) {
            return metrics(Output.of(metrics));
        }

        /**
         * @param metrics Trained Model Metrics.
         * 
         * @return builder
         * 
         */
        public Builder metrics(ModelMetricArgs... metrics) {
            return metrics(List.of(metrics));
        }

        public Builder modelId(@Nullable Output<String> modelId) {
            $.modelId = modelId;
            return this;
        }

        public Builder modelId(String modelId) {
            return modelId(Output.of(modelId));
        }

        /**
         * @param modelType The type of the Document model.
         * 
         * @return builder
         * 
         */
        public Builder modelType(@Nullable Output<String> modelType) {
            $.modelType = modelType;
            return this;
        }

        /**
         * @param modelType The type of the Document model.
         * 
         * @return builder
         * 
         */
        public Builder modelType(String modelType) {
            return modelType(Output.of(modelType));
        }

        /**
         * @param modelVersion The model version
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(@Nullable Output<String> modelVersion) {
            $.modelVersion = modelVersion;
            return this;
        }

        /**
         * @param modelVersion The model version
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(String modelVersion) {
            return modelVersion(Output.of(modelVersion));
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param state The current state of the model.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the model.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{&#34;orcl-cloud&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{&#34;orcl-cloud&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param tenancyId The tenancy id of the model.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(@Nullable Output<String> tenancyId) {
            $.tenancyId = tenancyId;
            return this;
        }

        /**
         * @param tenancyId The tenancy id of the model.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(String tenancyId) {
            return tenancyId(Output.of(tenancyId));
        }

        /**
         * @param testingDataset The base entity which is the input for creating and training a model.
         * 
         * @return builder
         * 
         */
        public Builder testingDataset(@Nullable Output<ModelTestingDatasetArgs> testingDataset) {
            $.testingDataset = testingDataset;
            return this;
        }

        /**
         * @param testingDataset The base entity which is the input for creating and training a model.
         * 
         * @return builder
         * 
         */
        public Builder testingDataset(ModelTestingDatasetArgs testingDataset) {
            return testingDataset(Output.of(testingDataset));
        }

        /**
         * @param timeCreated When the model was created, as an RFC3339 datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated When the model was created, as an RFC3339 datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated When the model was updated, as an RFC3339 datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated When the model was updated, as an RFC3339 datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param trainedTimeInHours The total hours actually used for model training.
         * 
         * @return builder
         * 
         */
        public Builder trainedTimeInHours(@Nullable Output<Double> trainedTimeInHours) {
            $.trainedTimeInHours = trainedTimeInHours;
            return this;
        }

        /**
         * @param trainedTimeInHours The total hours actually used for model training.
         * 
         * @return builder
         * 
         */
        public Builder trainedTimeInHours(Double trainedTimeInHours) {
            return trainedTimeInHours(Output.of(trainedTimeInHours));
        }

        /**
         * @param trainingDataset The base entity which is the input for creating and training a model.
         * 
         * @return builder
         * 
         */
        public Builder trainingDataset(@Nullable Output<ModelTrainingDatasetArgs> trainingDataset) {
            $.trainingDataset = trainingDataset;
            return this;
        }

        /**
         * @param trainingDataset The base entity which is the input for creating and training a model.
         * 
         * @return builder
         * 
         */
        public Builder trainingDataset(ModelTrainingDatasetArgs trainingDataset) {
            return trainingDataset(Output.of(trainingDataset));
        }

        /**
         * @param validationDataset The base entity which is the input for creating and training a model.
         * 
         * @return builder
         * 
         */
        public Builder validationDataset(@Nullable Output<ModelValidationDatasetArgs> validationDataset) {
            $.validationDataset = validationDataset;
            return this;
        }

        /**
         * @param validationDataset The base entity which is the input for creating and training a model.
         * 
         * @return builder
         * 
         */
        public Builder validationDataset(ModelValidationDatasetArgs validationDataset) {
            return validationDataset(Output.of(validationDataset));
        }

        public ModelState build() {
            return $;
        }
    }

}
