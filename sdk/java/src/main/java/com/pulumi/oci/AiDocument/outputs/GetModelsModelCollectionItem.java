// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.AiDocument.outputs.GetModelsModelCollectionItemMetric;
import com.pulumi.oci.AiDocument.outputs.GetModelsModelCollectionItemTestingDataset;
import com.pulumi.oci.AiDocument.outputs.GetModelsModelCollectionItemTrainingDataset;
import com.pulumi.oci.AiDocument.outputs.GetModelsModelCollectionItemValidationDataset;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return An optional description of the model.
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The filter to find the model with the given identifier.
     * 
     */
    private String id;
    /**
     * @return Set to true when experimenting with a new model type or dataset, so model training is quick, with a predefined low number of passes through the training data.
     * 
     */
    private Boolean isQuickMode;
    /**
     * @return The collection of labels used to train the custom model.
     * 
     */
    private List<String> labels;
    /**
     * @return A message describing the current state in more detail, that can provide actionable information if training failed.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The maximum model training time in hours, expressed as a decimal fraction.
     * 
     */
    private Double maxTrainingTimeInHours;
    /**
     * @return Trained Model Metrics.
     * 
     */
    private List<GetModelsModelCollectionItemMetric> metrics;
    /**
     * @return The type of the Document model.
     * 
     */
    private String modelType;
    /**
     * @return The version of the model.
     * 
     */
    private String modelVersion;
    /**
     * @return The ID of the project for which to list the objects.
     * 
     */
    private String projectId;
    /**
     * @return The filter to match models with the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{&#34;orcl-cloud&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    private List<GetModelsModelCollectionItemTestingDataset> testingDatasets;
    /**
     * @return When the model was created, as an RFC3339 datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return When the model was updated, as an RFC3339 datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return The total hours actually used for model training.
     * 
     */
    private Double trainedTimeInHours;
    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    private List<GetModelsModelCollectionItemTrainingDataset> trainingDatasets;
    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    private List<GetModelsModelCollectionItemValidationDataset> validationDatasets;

    private GetModelsModelCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return An optional description of the model.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The filter to find the model with the given identifier.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Set to true when experimenting with a new model type or dataset, so model training is quick, with a predefined low number of passes through the training data.
     * 
     */
    public Boolean isQuickMode() {
        return this.isQuickMode;
    }
    /**
     * @return The collection of labels used to train the custom model.
     * 
     */
    public List<String> labels() {
        return this.labels;
    }
    /**
     * @return A message describing the current state in more detail, that can provide actionable information if training failed.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The maximum model training time in hours, expressed as a decimal fraction.
     * 
     */
    public Double maxTrainingTimeInHours() {
        return this.maxTrainingTimeInHours;
    }
    /**
     * @return Trained Model Metrics.
     * 
     */
    public List<GetModelsModelCollectionItemMetric> metrics() {
        return this.metrics;
    }
    /**
     * @return The type of the Document model.
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return The version of the model.
     * 
     */
    public String modelVersion() {
        return this.modelVersion;
    }
    /**
     * @return The ID of the project for which to list the objects.
     * 
     */
    public String projectId() {
        return this.projectId;
    }
    /**
     * @return The filter to match models with the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{&#34;orcl-cloud&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    public List<GetModelsModelCollectionItemTestingDataset> testingDatasets() {
        return this.testingDatasets;
    }
    /**
     * @return When the model was created, as an RFC3339 datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return When the model was updated, as an RFC3339 datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The total hours actually used for model training.
     * 
     */
    public Double trainedTimeInHours() {
        return this.trainedTimeInHours;
    }
    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    public List<GetModelsModelCollectionItemTrainingDataset> trainingDatasets() {
        return this.trainingDatasets;
    }
    /**
     * @return The base entity which is the input for creating and training a model.
     * 
     */
    public List<GetModelsModelCollectionItemValidationDataset> validationDatasets() {
        return this.validationDatasets;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isQuickMode;
        private List<String> labels;
        private String lifecycleDetails;
        private Double maxTrainingTimeInHours;
        private List<GetModelsModelCollectionItemMetric> metrics;
        private String modelType;
        private String modelVersion;
        private String projectId;
        private String state;
        private Map<String,Object> systemTags;
        private List<GetModelsModelCollectionItemTestingDataset> testingDatasets;
        private String timeCreated;
        private String timeUpdated;
        private Double trainedTimeInHours;
        private List<GetModelsModelCollectionItemTrainingDataset> trainingDatasets;
        private List<GetModelsModelCollectionItemValidationDataset> validationDatasets;
        public Builder() {}
        public Builder(GetModelsModelCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isQuickMode = defaults.isQuickMode;
    	      this.labels = defaults.labels;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.maxTrainingTimeInHours = defaults.maxTrainingTimeInHours;
    	      this.metrics = defaults.metrics;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.testingDatasets = defaults.testingDatasets;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.trainedTimeInHours = defaults.trainedTimeInHours;
    	      this.trainingDatasets = defaults.trainingDatasets;
    	      this.validationDatasets = defaults.validationDatasets;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isQuickMode(Boolean isQuickMode) {
            this.isQuickMode = Objects.requireNonNull(isQuickMode);
            return this;
        }
        @CustomType.Setter
        public Builder labels(List<String> labels) {
            this.labels = Objects.requireNonNull(labels);
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder maxTrainingTimeInHours(Double maxTrainingTimeInHours) {
            this.maxTrainingTimeInHours = Objects.requireNonNull(maxTrainingTimeInHours);
            return this;
        }
        @CustomType.Setter
        public Builder metrics(List<GetModelsModelCollectionItemMetric> metrics) {
            this.metrics = Objects.requireNonNull(metrics);
            return this;
        }
        public Builder metrics(GetModelsModelCollectionItemMetric... metrics) {
            return metrics(List.of(metrics));
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            this.modelType = Objects.requireNonNull(modelType);
            return this;
        }
        @CustomType.Setter
        public Builder modelVersion(String modelVersion) {
            this.modelVersion = Objects.requireNonNull(modelVersion);
            return this;
        }
        @CustomType.Setter
        public Builder projectId(String projectId) {
            this.projectId = Objects.requireNonNull(projectId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder testingDatasets(List<GetModelsModelCollectionItemTestingDataset> testingDatasets) {
            this.testingDatasets = Objects.requireNonNull(testingDatasets);
            return this;
        }
        public Builder testingDatasets(GetModelsModelCollectionItemTestingDataset... testingDatasets) {
            return testingDatasets(List.of(testingDatasets));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder trainedTimeInHours(Double trainedTimeInHours) {
            this.trainedTimeInHours = Objects.requireNonNull(trainedTimeInHours);
            return this;
        }
        @CustomType.Setter
        public Builder trainingDatasets(List<GetModelsModelCollectionItemTrainingDataset> trainingDatasets) {
            this.trainingDatasets = Objects.requireNonNull(trainingDatasets);
            return this;
        }
        public Builder trainingDatasets(GetModelsModelCollectionItemTrainingDataset... trainingDatasets) {
            return trainingDatasets(List.of(trainingDatasets));
        }
        @CustomType.Setter
        public Builder validationDatasets(List<GetModelsModelCollectionItemValidationDataset> validationDatasets) {
            this.validationDatasets = Objects.requireNonNull(validationDatasets);
            return this;
        }
        public Builder validationDatasets(GetModelsModelCollectionItemValidationDataset... validationDatasets) {
            return validationDatasets(List.of(validationDatasets));
        }
        public GetModelsModelCollectionItem build() {
            final var o = new GetModelsModelCollectionItem();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isQuickMode = isQuickMode;
            o.labels = labels;
            o.lifecycleDetails = lifecycleDetails;
            o.maxTrainingTimeInHours = maxTrainingTimeInHours;
            o.metrics = metrics;
            o.modelType = modelType;
            o.modelVersion = modelVersion;
            o.projectId = projectId;
            o.state = state;
            o.systemTags = systemTags;
            o.testingDatasets = testingDatasets;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.trainedTimeInHours = trainedTimeInHours;
            o.trainingDatasets = trainingDatasets;
            o.validationDatasets = validationDatasets;
            return o;
        }
    }
}