// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiVision.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.AiVision.inputs.ModelTestingDatasetArgs;
import com.pulumi.oci.AiVision.inputs.ModelTrainingDatasetArgs;
import com.pulumi.oci.AiVision.inputs.ModelValidationDatasetArgs;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelState extends com.pulumi.resources.ResourceArgs {

    public static final ModelState Empty = new ModelState();

    /**
     * Average precision of the trained model
     * 
     */
    @Import(name="averagePrecision")
    private @Nullable Output<Double> averagePrecision;

    /**
     * @return Average precision of the trained model
     * 
     */
    public Optional<Output<Double>> averagePrecision() {
        return Optional.ofNullable(this.averagePrecision);
    }

    /**
     * (Updatable) Compartment Identifier
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Confidence ratio of the calculation
     * 
     */
    @Import(name="confidenceThreshold")
    private @Nullable Output<Double> confidenceThreshold;

    /**
     * @return Confidence ratio of the calculation
     * 
     */
    public Optional<Output<Double>> confidenceThreshold() {
        return Optional.ofNullable(this.confidenceThreshold);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A short description of the Model.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A short description of the Model.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Model Identifier
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Model Identifier
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * If It&#39;s true, Training is set for recommended epochs needed for quick training.
     * 
     */
    @Import(name="isQuickMode")
    private @Nullable Output<Boolean> isQuickMode;

    /**
     * @return If It&#39;s true, Training is set for recommended epochs needed for quick training.
     * 
     */
    public Optional<Output<Boolean>> isQuickMode() {
        return Optional.ofNullable(this.isQuickMode);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The maximum duration in hours for which the training will run.
     * 
     */
    @Import(name="maxTrainingDurationInHours")
    private @Nullable Output<Double> maxTrainingDurationInHours;

    /**
     * @return The maximum duration in hours for which the training will run.
     * 
     */
    public Optional<Output<Double>> maxTrainingDurationInHours() {
        return Optional.ofNullable(this.maxTrainingDurationInHours);
    }

    /**
     * Complete Training Metrics for successful trained model
     * 
     */
    @Import(name="metrics")
    private @Nullable Output<String> metrics;

    /**
     * @return Complete Training Metrics for successful trained model
     * 
     */
    public Optional<Output<String>> metrics() {
        return Optional.ofNullable(this.metrics);
    }

    /**
     * The  type of the model.
     * 
     */
    @Import(name="modelType")
    private @Nullable Output<String> modelType;

    /**
     * @return The  type of the model.
     * 
     */
    public Optional<Output<String>> modelType() {
        return Optional.ofNullable(this.modelType);
    }

    /**
     * Model version.
     * 
     */
    @Import(name="modelVersion")
    private @Nullable Output<String> modelVersion;

    /**
     * @return Model version.
     * 
     */
    public Optional<Output<String>> modelVersion() {
        return Optional.ofNullable(this.modelVersion);
    }

    /**
     * Precision of the trained model
     * 
     */
    @Import(name="precision")
    private @Nullable Output<Double> precision;

    /**
     * @return Precision of the trained model
     * 
     */
    public Optional<Output<Double>> precision() {
        return Optional.ofNullable(this.precision);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    @Import(name="projectId")
    private @Nullable Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    public Optional<Output<String>> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * Recall of the trained model
     * 
     */
    @Import(name="recall")
    private @Nullable Output<Double> recall;

    /**
     * @return Recall of the trained model
     * 
     */
    public Optional<Output<Double>> recall() {
        return Optional.ofNullable(this.recall);
    }

    /**
     * The current state of the Model.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Model.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * Total number of testing Images
     * 
     */
    @Import(name="testImageCount")
    private @Nullable Output<Integer> testImageCount;

    /**
     * @return Total number of testing Images
     * 
     */
    public Optional<Output<Integer>> testImageCount() {
        return Optional.ofNullable(this.testImageCount);
    }

    /**
     * The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    @Import(name="testingDataset")
    private @Nullable Output<ModelTestingDatasetArgs> testingDataset;

    /**
     * @return The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    public Optional<Output<ModelTestingDatasetArgs>> testingDataset() {
        return Optional.ofNullable(this.testingDataset);
    }

    /**
     * The time the Model was created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the Model was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the Model was updated. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the Model was updated. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * Total number of training Images
     * 
     */
    @Import(name="totalImageCount")
    private @Nullable Output<Integer> totalImageCount;

    /**
     * @return Total number of training Images
     * 
     */
    public Optional<Output<Integer>> totalImageCount() {
        return Optional.ofNullable(this.totalImageCount);
    }

    /**
     * Total hours actually used for training
     * 
     */
    @Import(name="trainedDurationInHours")
    private @Nullable Output<Double> trainedDurationInHours;

    /**
     * @return Total hours actually used for training
     * 
     */
    public Optional<Output<Double>> trainedDurationInHours() {
        return Optional.ofNullable(this.trainedDurationInHours);
    }

    /**
     * The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    @Import(name="trainingDataset")
    private @Nullable Output<ModelTrainingDatasetArgs> trainingDataset;

    /**
     * @return The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    public Optional<Output<ModelTrainingDatasetArgs>> trainingDataset() {
        return Optional.ofNullable(this.trainingDataset);
    }

    /**
     * The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    @Import(name="validationDataset")
    private @Nullable Output<ModelValidationDatasetArgs> validationDataset;

    /**
     * @return The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    public Optional<Output<ModelValidationDatasetArgs>> validationDataset() {
        return Optional.ofNullable(this.validationDataset);
    }

    private ModelState() {}

    private ModelState(ModelState $) {
        this.averagePrecision = $.averagePrecision;
        this.compartmentId = $.compartmentId;
        this.confidenceThreshold = $.confidenceThreshold;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isQuickMode = $.isQuickMode;
        this.lifecycleDetails = $.lifecycleDetails;
        this.maxTrainingDurationInHours = $.maxTrainingDurationInHours;
        this.metrics = $.metrics;
        this.modelType = $.modelType;
        this.modelVersion = $.modelVersion;
        this.precision = $.precision;
        this.projectId = $.projectId;
        this.recall = $.recall;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.testImageCount = $.testImageCount;
        this.testingDataset = $.testingDataset;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.totalImageCount = $.totalImageCount;
        this.trainedDurationInHours = $.trainedDurationInHours;
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
         * @param averagePrecision Average precision of the trained model
         * 
         * @return builder
         * 
         */
        public Builder averagePrecision(@Nullable Output<Double> averagePrecision) {
            $.averagePrecision = averagePrecision;
            return this;
        }

        /**
         * @param averagePrecision Average precision of the trained model
         * 
         * @return builder
         * 
         */
        public Builder averagePrecision(Double averagePrecision) {
            return averagePrecision(Output.of(averagePrecision));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param confidenceThreshold Confidence ratio of the calculation
         * 
         * @return builder
         * 
         */
        public Builder confidenceThreshold(@Nullable Output<Double> confidenceThreshold) {
            $.confidenceThreshold = confidenceThreshold;
            return this;
        }

        /**
         * @param confidenceThreshold Confidence ratio of the calculation
         * 
         * @return builder
         * 
         */
        public Builder confidenceThreshold(Double confidenceThreshold) {
            return confidenceThreshold(Output.of(confidenceThreshold));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A short description of the Model.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A short description of the Model.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Model Identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Model Identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isQuickMode If It&#39;s true, Training is set for recommended epochs needed for quick training.
         * 
         * @return builder
         * 
         */
        public Builder isQuickMode(@Nullable Output<Boolean> isQuickMode) {
            $.isQuickMode = isQuickMode;
            return this;
        }

        /**
         * @param isQuickMode If It&#39;s true, Training is set for recommended epochs needed for quick training.
         * 
         * @return builder
         * 
         */
        public Builder isQuickMode(Boolean isQuickMode) {
            return isQuickMode(Output.of(isQuickMode));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param maxTrainingDurationInHours The maximum duration in hours for which the training will run.
         * 
         * @return builder
         * 
         */
        public Builder maxTrainingDurationInHours(@Nullable Output<Double> maxTrainingDurationInHours) {
            $.maxTrainingDurationInHours = maxTrainingDurationInHours;
            return this;
        }

        /**
         * @param maxTrainingDurationInHours The maximum duration in hours for which the training will run.
         * 
         * @return builder
         * 
         */
        public Builder maxTrainingDurationInHours(Double maxTrainingDurationInHours) {
            return maxTrainingDurationInHours(Output.of(maxTrainingDurationInHours));
        }

        /**
         * @param metrics Complete Training Metrics for successful trained model
         * 
         * @return builder
         * 
         */
        public Builder metrics(@Nullable Output<String> metrics) {
            $.metrics = metrics;
            return this;
        }

        /**
         * @param metrics Complete Training Metrics for successful trained model
         * 
         * @return builder
         * 
         */
        public Builder metrics(String metrics) {
            return metrics(Output.of(metrics));
        }

        /**
         * @param modelType The  type of the model.
         * 
         * @return builder
         * 
         */
        public Builder modelType(@Nullable Output<String> modelType) {
            $.modelType = modelType;
            return this;
        }

        /**
         * @param modelType The  type of the model.
         * 
         * @return builder
         * 
         */
        public Builder modelType(String modelType) {
            return modelType(Output.of(modelType));
        }

        /**
         * @param modelVersion Model version.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(@Nullable Output<String> modelVersion) {
            $.modelVersion = modelVersion;
            return this;
        }

        /**
         * @param modelVersion Model version.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(String modelVersion) {
            return modelVersion(Output.of(modelVersion));
        }

        /**
         * @param precision Precision of the trained model
         * 
         * @return builder
         * 
         */
        public Builder precision(@Nullable Output<Double> precision) {
            $.precision = precision;
            return this;
        }

        /**
         * @param precision Precision of the trained model
         * 
         * @return builder
         * 
         */
        public Builder precision(Double precision) {
            return precision(Output.of(precision));
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param recall Recall of the trained model
         * 
         * @return builder
         * 
         */
        public Builder recall(@Nullable Output<Double> recall) {
            $.recall = recall;
            return this;
        }

        /**
         * @param recall Recall of the trained model
         * 
         * @return builder
         * 
         */
        public Builder recall(Double recall) {
            return recall(Output.of(recall));
        }

        /**
         * @param state The current state of the Model.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Model.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,Object>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,Object> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param testImageCount Total number of testing Images
         * 
         * @return builder
         * 
         */
        public Builder testImageCount(@Nullable Output<Integer> testImageCount) {
            $.testImageCount = testImageCount;
            return this;
        }

        /**
         * @param testImageCount Total number of testing Images
         * 
         * @return builder
         * 
         */
        public Builder testImageCount(Integer testImageCount) {
            return testImageCount(Output.of(testImageCount));
        }

        /**
         * @param testingDataset The base entity for a Dataset, which is the input for Model creation.
         * 
         * @return builder
         * 
         */
        public Builder testingDataset(@Nullable Output<ModelTestingDatasetArgs> testingDataset) {
            $.testingDataset = testingDataset;
            return this;
        }

        /**
         * @param testingDataset The base entity for a Dataset, which is the input for Model creation.
         * 
         * @return builder
         * 
         */
        public Builder testingDataset(ModelTestingDatasetArgs testingDataset) {
            return testingDataset(Output.of(testingDataset));
        }

        /**
         * @param timeCreated The time the Model was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the Model was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the Model was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the Model was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param totalImageCount Total number of training Images
         * 
         * @return builder
         * 
         */
        public Builder totalImageCount(@Nullable Output<Integer> totalImageCount) {
            $.totalImageCount = totalImageCount;
            return this;
        }

        /**
         * @param totalImageCount Total number of training Images
         * 
         * @return builder
         * 
         */
        public Builder totalImageCount(Integer totalImageCount) {
            return totalImageCount(Output.of(totalImageCount));
        }

        /**
         * @param trainedDurationInHours Total hours actually used for training
         * 
         * @return builder
         * 
         */
        public Builder trainedDurationInHours(@Nullable Output<Double> trainedDurationInHours) {
            $.trainedDurationInHours = trainedDurationInHours;
            return this;
        }

        /**
         * @param trainedDurationInHours Total hours actually used for training
         * 
         * @return builder
         * 
         */
        public Builder trainedDurationInHours(Double trainedDurationInHours) {
            return trainedDurationInHours(Output.of(trainedDurationInHours));
        }

        /**
         * @param trainingDataset The base entity for a Dataset, which is the input for Model creation.
         * 
         * @return builder
         * 
         */
        public Builder trainingDataset(@Nullable Output<ModelTrainingDatasetArgs> trainingDataset) {
            $.trainingDataset = trainingDataset;
            return this;
        }

        /**
         * @param trainingDataset The base entity for a Dataset, which is the input for Model creation.
         * 
         * @return builder
         * 
         */
        public Builder trainingDataset(ModelTrainingDatasetArgs trainingDataset) {
            return trainingDataset(Output.of(trainingDataset));
        }

        /**
         * @param validationDataset The base entity for a Dataset, which is the input for Model creation.
         * 
         * @return builder
         * 
         */
        public Builder validationDataset(@Nullable Output<ModelValidationDatasetArgs> validationDataset) {
            $.validationDataset = validationDataset;
            return this;
        }

        /**
         * @param validationDataset The base entity for a Dataset, which is the input for Model creation.
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