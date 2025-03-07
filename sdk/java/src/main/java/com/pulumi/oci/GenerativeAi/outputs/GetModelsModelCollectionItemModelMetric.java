// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemModelMetric {
    /**
     * @return Fine-tuned model accuracy.
     * 
     */
    private Double finalAccuracy;
    /**
     * @return Fine-tuned model loss.
     * 
     */
    private Double finalLoss;
    /**
     * @return The type of the model metrics. Each type of model can expect a different set of model metrics.
     * 
     */
    private String modelMetricsType;

    private GetModelsModelCollectionItemModelMetric() {}
    /**
     * @return Fine-tuned model accuracy.
     * 
     */
    public Double finalAccuracy() {
        return this.finalAccuracy;
    }
    /**
     * @return Fine-tuned model loss.
     * 
     */
    public Double finalLoss() {
        return this.finalLoss;
    }
    /**
     * @return The type of the model metrics. Each type of model can expect a different set of model metrics.
     * 
     */
    public String modelMetricsType() {
        return this.modelMetricsType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItemModelMetric defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double finalAccuracy;
        private Double finalLoss;
        private String modelMetricsType;
        public Builder() {}
        public Builder(GetModelsModelCollectionItemModelMetric defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.finalAccuracy = defaults.finalAccuracy;
    	      this.finalLoss = defaults.finalLoss;
    	      this.modelMetricsType = defaults.modelMetricsType;
        }

        @CustomType.Setter
        public Builder finalAccuracy(Double finalAccuracy) {
            if (finalAccuracy == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemModelMetric", "finalAccuracy");
            }
            this.finalAccuracy = finalAccuracy;
            return this;
        }
        @CustomType.Setter
        public Builder finalLoss(Double finalLoss) {
            if (finalLoss == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemModelMetric", "finalLoss");
            }
            this.finalLoss = finalLoss;
            return this;
        }
        @CustomType.Setter
        public Builder modelMetricsType(String modelMetricsType) {
            if (modelMetricsType == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemModelMetric", "modelMetricsType");
            }
            this.modelMetricsType = modelMetricsType;
            return this;
        }
        public GetModelsModelCollectionItemModelMetric build() {
            final var _resultValue = new GetModelsModelCollectionItemModelMetric();
            _resultValue.finalAccuracy = finalAccuracy;
            _resultValue.finalLoss = finalLoss;
            _resultValue.modelMetricsType = modelMetricsType;
            return _resultValue;
        }
    }
}
