// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.outputs.GetModelFineTuneDetailTrainingConfig;
import com.pulumi.oci.GenerativeAi.outputs.GetModelFineTuneDetailTrainingDataset;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelFineTuneDetail {
    /**
     * @return The OCID of the dedicated AI cluster this fine-tuning runs on.
     * 
     */
    private String dedicatedAiClusterId;
    /**
     * @return The fine-tuning method and hyperparameters used for fine-tuning a custom model.
     * 
     */
    private List<GetModelFineTuneDetailTrainingConfig> trainingConfigs;
    /**
     * @return The dataset used to fine-tune the model.
     * 
     */
    private List<GetModelFineTuneDetailTrainingDataset> trainingDatasets;

    private GetModelFineTuneDetail() {}
    /**
     * @return The OCID of the dedicated AI cluster this fine-tuning runs on.
     * 
     */
    public String dedicatedAiClusterId() {
        return this.dedicatedAiClusterId;
    }
    /**
     * @return The fine-tuning method and hyperparameters used for fine-tuning a custom model.
     * 
     */
    public List<GetModelFineTuneDetailTrainingConfig> trainingConfigs() {
        return this.trainingConfigs;
    }
    /**
     * @return The dataset used to fine-tune the model.
     * 
     */
    public List<GetModelFineTuneDetailTrainingDataset> trainingDatasets() {
        return this.trainingDatasets;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelFineTuneDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dedicatedAiClusterId;
        private List<GetModelFineTuneDetailTrainingConfig> trainingConfigs;
        private List<GetModelFineTuneDetailTrainingDataset> trainingDatasets;
        public Builder() {}
        public Builder(GetModelFineTuneDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dedicatedAiClusterId = defaults.dedicatedAiClusterId;
    	      this.trainingConfigs = defaults.trainingConfigs;
    	      this.trainingDatasets = defaults.trainingDatasets;
        }

        @CustomType.Setter
        public Builder dedicatedAiClusterId(String dedicatedAiClusterId) {
            if (dedicatedAiClusterId == null) {
              throw new MissingRequiredPropertyException("GetModelFineTuneDetail", "dedicatedAiClusterId");
            }
            this.dedicatedAiClusterId = dedicatedAiClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder trainingConfigs(List<GetModelFineTuneDetailTrainingConfig> trainingConfigs) {
            if (trainingConfigs == null) {
              throw new MissingRequiredPropertyException("GetModelFineTuneDetail", "trainingConfigs");
            }
            this.trainingConfigs = trainingConfigs;
            return this;
        }
        public Builder trainingConfigs(GetModelFineTuneDetailTrainingConfig... trainingConfigs) {
            return trainingConfigs(List.of(trainingConfigs));
        }
        @CustomType.Setter
        public Builder trainingDatasets(List<GetModelFineTuneDetailTrainingDataset> trainingDatasets) {
            if (trainingDatasets == null) {
              throw new MissingRequiredPropertyException("GetModelFineTuneDetail", "trainingDatasets");
            }
            this.trainingDatasets = trainingDatasets;
            return this;
        }
        public Builder trainingDatasets(GetModelFineTuneDetailTrainingDataset... trainingDatasets) {
            return trainingDatasets(List.of(trainingDatasets));
        }
        public GetModelFineTuneDetail build() {
            final var _resultValue = new GetModelFineTuneDetail();
            _resultValue.dedicatedAiClusterId = dedicatedAiClusterId;
            _resultValue.trainingConfigs = trainingConfigs;
            _resultValue.trainingDatasets = trainingDatasets;
            return _resultValue;
        }
    }
}
