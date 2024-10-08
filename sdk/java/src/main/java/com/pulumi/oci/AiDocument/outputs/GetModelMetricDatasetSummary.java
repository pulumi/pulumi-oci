// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetModelMetricDatasetSummary {
    /**
     * @return Number of samples used for testing the model.
     * 
     */
    private Integer testSampleCount;
    /**
     * @return Number of samples used for training the model.
     * 
     */
    private Integer trainingSampleCount;
    /**
     * @return Number of samples used for validating the model.
     * 
     */
    private Integer validationSampleCount;

    private GetModelMetricDatasetSummary() {}
    /**
     * @return Number of samples used for testing the model.
     * 
     */
    public Integer testSampleCount() {
        return this.testSampleCount;
    }
    /**
     * @return Number of samples used for training the model.
     * 
     */
    public Integer trainingSampleCount() {
        return this.trainingSampleCount;
    }
    /**
     * @return Number of samples used for validating the model.
     * 
     */
    public Integer validationSampleCount() {
        return this.validationSampleCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelMetricDatasetSummary defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer testSampleCount;
        private Integer trainingSampleCount;
        private Integer validationSampleCount;
        public Builder() {}
        public Builder(GetModelMetricDatasetSummary defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.testSampleCount = defaults.testSampleCount;
    	      this.trainingSampleCount = defaults.trainingSampleCount;
    	      this.validationSampleCount = defaults.validationSampleCount;
        }

        @CustomType.Setter
        public Builder testSampleCount(Integer testSampleCount) {
            if (testSampleCount == null) {
              throw new MissingRequiredPropertyException("GetModelMetricDatasetSummary", "testSampleCount");
            }
            this.testSampleCount = testSampleCount;
            return this;
        }
        @CustomType.Setter
        public Builder trainingSampleCount(Integer trainingSampleCount) {
            if (trainingSampleCount == null) {
              throw new MissingRequiredPropertyException("GetModelMetricDatasetSummary", "trainingSampleCount");
            }
            this.trainingSampleCount = trainingSampleCount;
            return this;
        }
        @CustomType.Setter
        public Builder validationSampleCount(Integer validationSampleCount) {
            if (validationSampleCount == null) {
              throw new MissingRequiredPropertyException("GetModelMetricDatasetSummary", "validationSampleCount");
            }
            this.validationSampleCount = validationSampleCount;
            return this;
        }
        public GetModelMetricDatasetSummary build() {
            final var _resultValue = new GetModelMetricDatasetSummary();
            _resultValue.testSampleCount = testSampleCount;
            _resultValue.trainingSampleCount = trainingSampleCount;
            _resultValue.validationSampleCount = validationSampleCount;
            return _resultValue;
        }
    }
}
