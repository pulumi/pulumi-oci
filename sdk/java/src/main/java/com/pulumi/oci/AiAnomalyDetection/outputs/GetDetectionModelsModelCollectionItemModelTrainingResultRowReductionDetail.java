// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectionModelsModelCollectionItemModelTrainingResultRowReductionDetail {
    /**
     * @return A boolean value to indicate if row reduction is applied
     * 
     */
    private Boolean isReductionEnabled;
    /**
     * @return Method for row reduction:
     * * DELETE_ROW - delete rows with equal intervals
     * * AVERAGE_ROW - average multiple rows to one row
     * 
     */
    private String reductionMethod;
    /**
     * @return A percentage to reduce data size down to on top of original data
     * 
     */
    private Double reductionPercentage;

    private GetDetectionModelsModelCollectionItemModelTrainingResultRowReductionDetail() {}
    /**
     * @return A boolean value to indicate if row reduction is applied
     * 
     */
    public Boolean isReductionEnabled() {
        return this.isReductionEnabled;
    }
    /**
     * @return Method for row reduction:
     * * DELETE_ROW - delete rows with equal intervals
     * * AVERAGE_ROW - average multiple rows to one row
     * 
     */
    public String reductionMethod() {
        return this.reductionMethod;
    }
    /**
     * @return A percentage to reduce data size down to on top of original data
     * 
     */
    public Double reductionPercentage() {
        return this.reductionPercentage;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectionModelsModelCollectionItemModelTrainingResultRowReductionDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isReductionEnabled;
        private String reductionMethod;
        private Double reductionPercentage;
        public Builder() {}
        public Builder(GetDetectionModelsModelCollectionItemModelTrainingResultRowReductionDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isReductionEnabled = defaults.isReductionEnabled;
    	      this.reductionMethod = defaults.reductionMethod;
    	      this.reductionPercentage = defaults.reductionPercentage;
        }

        @CustomType.Setter
        public Builder isReductionEnabled(Boolean isReductionEnabled) {
            this.isReductionEnabled = Objects.requireNonNull(isReductionEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder reductionMethod(String reductionMethod) {
            this.reductionMethod = Objects.requireNonNull(reductionMethod);
            return this;
        }
        @CustomType.Setter
        public Builder reductionPercentage(Double reductionPercentage) {
            this.reductionPercentage = Objects.requireNonNull(reductionPercentage);
            return this;
        }
        public GetDetectionModelsModelCollectionItemModelTrainingResultRowReductionDetail build() {
            final var o = new GetDetectionModelsModelCollectionItemModelTrainingResultRowReductionDetail();
            o.isReductionEnabled = isReductionEnabled;
            o.reductionMethod = reductionMethod;
            o.reductionPercentage = reductionPercentage;
            return o;
        }
    }
}