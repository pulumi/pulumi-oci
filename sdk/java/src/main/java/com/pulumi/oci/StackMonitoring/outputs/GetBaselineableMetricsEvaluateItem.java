// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.outputs.GetBaselineableMetricsEvaluateItemDataPoint;
import com.pulumi.oci.StackMonitoring.outputs.GetBaselineableMetricsEvaluateItemEvaluationDataPoint;
import com.pulumi.oci.StackMonitoring.outputs.GetBaselineableMetricsEvaluateItemTrainingDataPoint;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetBaselineableMetricsEvaluateItem {
    /**
     * @return list of anomaly data points for the metric
     * 
     */
    private List<GetBaselineableMetricsEvaluateItemDataPoint> dataPoints;
    /**
     * @return list of dimensions for the metric
     * 
     */
    private Map<String,String> dimensions;
    /**
     * @return list of data points for the metric for evaluation of anomalies
     * 
     */
    private List<GetBaselineableMetricsEvaluateItemEvaluationDataPoint> evaluationDataPoints;
    /**
     * @return list of data points for the metric for training of baseline
     * 
     */
    private List<GetBaselineableMetricsEvaluateItemTrainingDataPoint> trainingDataPoints;

    private GetBaselineableMetricsEvaluateItem() {}
    /**
     * @return list of anomaly data points for the metric
     * 
     */
    public List<GetBaselineableMetricsEvaluateItemDataPoint> dataPoints() {
        return this.dataPoints;
    }
    /**
     * @return list of dimensions for the metric
     * 
     */
    public Map<String,String> dimensions() {
        return this.dimensions;
    }
    /**
     * @return list of data points for the metric for evaluation of anomalies
     * 
     */
    public List<GetBaselineableMetricsEvaluateItemEvaluationDataPoint> evaluationDataPoints() {
        return this.evaluationDataPoints;
    }
    /**
     * @return list of data points for the metric for training of baseline
     * 
     */
    public List<GetBaselineableMetricsEvaluateItemTrainingDataPoint> trainingDataPoints() {
        return this.trainingDataPoints;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBaselineableMetricsEvaluateItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBaselineableMetricsEvaluateItemDataPoint> dataPoints;
        private Map<String,String> dimensions;
        private List<GetBaselineableMetricsEvaluateItemEvaluationDataPoint> evaluationDataPoints;
        private List<GetBaselineableMetricsEvaluateItemTrainingDataPoint> trainingDataPoints;
        public Builder() {}
        public Builder(GetBaselineableMetricsEvaluateItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataPoints = defaults.dataPoints;
    	      this.dimensions = defaults.dimensions;
    	      this.evaluationDataPoints = defaults.evaluationDataPoints;
    	      this.trainingDataPoints = defaults.trainingDataPoints;
        }

        @CustomType.Setter
        public Builder dataPoints(List<GetBaselineableMetricsEvaluateItemDataPoint> dataPoints) {
            if (dataPoints == null) {
              throw new MissingRequiredPropertyException("GetBaselineableMetricsEvaluateItem", "dataPoints");
            }
            this.dataPoints = dataPoints;
            return this;
        }
        public Builder dataPoints(GetBaselineableMetricsEvaluateItemDataPoint... dataPoints) {
            return dataPoints(List.of(dataPoints));
        }
        @CustomType.Setter
        public Builder dimensions(Map<String,String> dimensions) {
            if (dimensions == null) {
              throw new MissingRequiredPropertyException("GetBaselineableMetricsEvaluateItem", "dimensions");
            }
            this.dimensions = dimensions;
            return this;
        }
        @CustomType.Setter
        public Builder evaluationDataPoints(List<GetBaselineableMetricsEvaluateItemEvaluationDataPoint> evaluationDataPoints) {
            if (evaluationDataPoints == null) {
              throw new MissingRequiredPropertyException("GetBaselineableMetricsEvaluateItem", "evaluationDataPoints");
            }
            this.evaluationDataPoints = evaluationDataPoints;
            return this;
        }
        public Builder evaluationDataPoints(GetBaselineableMetricsEvaluateItemEvaluationDataPoint... evaluationDataPoints) {
            return evaluationDataPoints(List.of(evaluationDataPoints));
        }
        @CustomType.Setter
        public Builder trainingDataPoints(List<GetBaselineableMetricsEvaluateItemTrainingDataPoint> trainingDataPoints) {
            if (trainingDataPoints == null) {
              throw new MissingRequiredPropertyException("GetBaselineableMetricsEvaluateItem", "trainingDataPoints");
            }
            this.trainingDataPoints = trainingDataPoints;
            return this;
        }
        public Builder trainingDataPoints(GetBaselineableMetricsEvaluateItemTrainingDataPoint... trainingDataPoints) {
            return trainingDataPoints(List.of(trainingDataPoints));
        }
        public GetBaselineableMetricsEvaluateItem build() {
            final var _resultValue = new GetBaselineableMetricsEvaluateItem();
            _resultValue.dataPoints = dataPoints;
            _resultValue.dimensions = dimensions;
            _resultValue.evaluationDataPoints = evaluationDataPoints;
            _resultValue.trainingDataPoints = trainingDataPoints;
            return _resultValue;
        }
    }
}
