// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.outputs.GetModelEvaluationResult;
import com.pulumi.oci.AiLanguage.outputs.GetModelModelDetail;
import com.pulumi.oci.AiLanguage.outputs.GetModelTestStrategy;
import com.pulumi.oci.AiLanguage.outputs.GetModelTrainingDataset;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetModelResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)  for the model&#39;s compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A short description of the Model.
     * 
     */
    private String description;
    /**
     * @return A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return model training results of different models
     * 
     */
    private List<GetModelEvaluationResult> evaluationResults;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Unique identifier model OCID of a model that is immutable on creation
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Possible model types
     * 
     */
    private List<GetModelModelDetail> modelDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    private String projectId;
    /**
     * @return The state of the model.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return Possible strategy as testing and validation(optional) dataset.
     * 
     */
    private List<GetModelTestStrategy> testStrategies;
    /**
     * @return The time the the model was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the model was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return Possible data set type
     * 
     */
    private List<GetModelTrainingDataset> trainingDatasets;
    /**
     * @return For pre trained models this will identify model type version used for model creation For custom identifying the model by model id is difficult. This param provides ease of use for end customer. &lt;&lt;service&gt;&gt;::&lt;&lt;service-name&gt;&gt;_&lt;&lt;model-type-version&gt;&gt;::&lt;&lt;custom model on which this training has to be done&gt;&gt; ex: ai-lang::NER_V1::CUSTOM-V0
     * 
     */
    private String version;

    private GetModelResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)  for the model&#39;s compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A short description of the Model.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return model training results of different models
     * 
     */
    public List<GetModelEvaluationResult> evaluationResults() {
        return this.evaluationResults;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique identifier model OCID of a model that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Possible model types
     * 
     */
    public List<GetModelModelDetail> modelDetails() {
        return this.modelDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    public String projectId() {
        return this.projectId;
    }
    /**
     * @return The state of the model.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Possible strategy as testing and validation(optional) dataset.
     * 
     */
    public List<GetModelTestStrategy> testStrategies() {
        return this.testStrategies;
    }
    /**
     * @return The time the the model was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the model was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Possible data set type
     * 
     */
    public List<GetModelTrainingDataset> trainingDatasets() {
        return this.trainingDatasets;
    }
    /**
     * @return For pre trained models this will identify model type version used for model creation For custom identifying the model by model id is difficult. This param provides ease of use for end customer. &lt;&lt;service&gt;&gt;::&lt;&lt;service-name&gt;&gt;_&lt;&lt;model-type-version&gt;&gt;::&lt;&lt;custom model on which this training has to be done&gt;&gt; ex: ai-lang::NER_V1::CUSTOM-V0
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private List<GetModelEvaluationResult> evaluationResults;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<GetModelModelDetail> modelDetails;
        private String projectId;
        private String state;
        private Map<String,String> systemTags;
        private List<GetModelTestStrategy> testStrategies;
        private String timeCreated;
        private String timeUpdated;
        private List<GetModelTrainingDataset> trainingDatasets;
        private String version;
        public Builder() {}
        public Builder(GetModelResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.evaluationResults = defaults.evaluationResults;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.modelDetails = defaults.modelDetails;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.testStrategies = defaults.testStrategies;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.trainingDatasets = defaults.trainingDatasets;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder evaluationResults(List<GetModelEvaluationResult> evaluationResults) {
            if (evaluationResults == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "evaluationResults");
            }
            this.evaluationResults = evaluationResults;
            return this;
        }
        public Builder evaluationResults(GetModelEvaluationResult... evaluationResults) {
            return evaluationResults(List.of(evaluationResults));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder modelDetails(List<GetModelModelDetail> modelDetails) {
            if (modelDetails == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "modelDetails");
            }
            this.modelDetails = modelDetails;
            return this;
        }
        public Builder modelDetails(GetModelModelDetail... modelDetails) {
            return modelDetails(List.of(modelDetails));
        }
        @CustomType.Setter
        public Builder projectId(String projectId) {
            if (projectId == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "projectId");
            }
            this.projectId = projectId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder testStrategies(List<GetModelTestStrategy> testStrategies) {
            if (testStrategies == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "testStrategies");
            }
            this.testStrategies = testStrategies;
            return this;
        }
        public Builder testStrategies(GetModelTestStrategy... testStrategies) {
            return testStrategies(List.of(testStrategies));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder trainingDatasets(List<GetModelTrainingDataset> trainingDatasets) {
            if (trainingDatasets == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "trainingDatasets");
            }
            this.trainingDatasets = trainingDatasets;
            return this;
        }
        public Builder trainingDatasets(GetModelTrainingDataset... trainingDatasets) {
            return trainingDatasets(List.of(trainingDatasets));
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetModelResult", "version");
            }
            this.version = version;
            return this;
        }
        public GetModelResult build() {
            final var _resultValue = new GetModelResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.evaluationResults = evaluationResults;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.modelDetails = modelDetails;
            _resultValue.projectId = projectId;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.testStrategies = testStrategies;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.trainingDatasets = trainingDatasets;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
