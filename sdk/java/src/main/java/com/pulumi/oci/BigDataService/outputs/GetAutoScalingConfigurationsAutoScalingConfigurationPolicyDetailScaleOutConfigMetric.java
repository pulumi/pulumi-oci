// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetricThreshold;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric {
    private String metricType;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetricThreshold> thresholds;

    private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric() {}
    public String metricType() {
        return this.metricType;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetricThreshold> thresholds() {
        return this.thresholds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String metricType;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetricThreshold> thresholds;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.metricType = defaults.metricType;
    	      this.thresholds = defaults.thresholds;
        }

        @CustomType.Setter
        public Builder metricType(String metricType) {
            if (metricType == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric", "metricType");
            }
            this.metricType = metricType;
            return this;
        }
        @CustomType.Setter
        public Builder thresholds(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetricThreshold> thresholds) {
            if (thresholds == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric", "thresholds");
            }
            this.thresholds = thresholds;
            return this;
        }
        public Builder thresholds(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetricThreshold... thresholds) {
            return thresholds(List.of(thresholds));
        }
        public GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric build() {
            final var _resultValue = new GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleOutConfigMetric();
            _resultValue.metricType = metricType;
            _resultValue.thresholds = thresholds;
            return _resultValue;
        }
    }
}
