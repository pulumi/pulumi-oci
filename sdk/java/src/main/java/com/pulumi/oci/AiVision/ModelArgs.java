// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiVision;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiVision.inputs.ModelTestingDatasetArgs;
import com.pulumi.oci.AiVision.inputs.ModelTrainingDatasetArgs;
import com.pulumi.oci.AiVision.inputs.ModelValidationDatasetArgs;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelArgs Empty = new ModelArgs();

    /**
     * (Updatable) Compartment Identifier
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
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
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
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
     * The  type of the model.
     * 
     */
    @Import(name="modelType", required=true)
    private Output<String> modelType;

    /**
     * @return The  type of the model.
     * 
     */
    public Output<String> modelType() {
        return this.modelType;
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
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    @Import(name="projectId", required=true)
    private Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
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
     * The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    @Import(name="trainingDataset", required=true)
    private Output<ModelTrainingDatasetArgs> trainingDataset;

    /**
     * @return The base entity for a Dataset, which is the input for Model creation.
     * 
     */
    public Output<ModelTrainingDatasetArgs> trainingDataset() {
        return this.trainingDataset;
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

    private ModelArgs() {}

    private ModelArgs(ModelArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isQuickMode = $.isQuickMode;
        this.maxTrainingDurationInHours = $.maxTrainingDurationInHours;
        this.modelType = $.modelType;
        this.modelVersion = $.modelVersion;
        this.projectId = $.projectId;
        this.testingDataset = $.testingDataset;
        this.trainingDataset = $.trainingDataset;
        this.validationDataset = $.validationDataset;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelArgs $;

        public Builder() {
            $ = new ModelArgs();
        }

        public Builder(ModelArgs defaults) {
            $ = new ModelArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
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
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
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
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
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
         * @param modelType The  type of the model.
         * 
         * @return builder
         * 
         */
        public Builder modelType(Output<String> modelType) {
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
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(Output<String> projectId) {
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
         * @param trainingDataset The base entity for a Dataset, which is the input for Model creation.
         * 
         * @return builder
         * 
         */
        public Builder trainingDataset(Output<ModelTrainingDatasetArgs> trainingDataset) {
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

        public ModelArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "compartmentId");
            }
            if ($.modelType == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "modelType");
            }
            if ($.projectId == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "projectId");
            }
            if ($.trainingDataset == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "trainingDataset");
            }
            return $;
        }
    }

}
