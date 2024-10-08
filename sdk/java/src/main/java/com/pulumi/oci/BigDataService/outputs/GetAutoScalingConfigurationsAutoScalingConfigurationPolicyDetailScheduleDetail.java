// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndHorizontalScalingConfig;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndVerticalScalingConfig;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail {
    private String scheduleType;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs;

    private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail() {}
    public String scheduleType() {
        return this.scheduleType;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs() {
        return this.timeAndHorizontalScalingConfigs;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs() {
        return this.timeAndVerticalScalingConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String scheduleType;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.scheduleType = defaults.scheduleType;
    	      this.timeAndHorizontalScalingConfigs = defaults.timeAndHorizontalScalingConfigs;
    	      this.timeAndVerticalScalingConfigs = defaults.timeAndVerticalScalingConfigs;
        }

        @CustomType.Setter
        public Builder scheduleType(String scheduleType) {
            if (scheduleType == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail", "scheduleType");
            }
            this.scheduleType = scheduleType;
            return this;
        }
        @CustomType.Setter
        public Builder timeAndHorizontalScalingConfigs(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs) {
            if (timeAndHorizontalScalingConfigs == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail", "timeAndHorizontalScalingConfigs");
            }
            this.timeAndHorizontalScalingConfigs = timeAndHorizontalScalingConfigs;
            return this;
        }
        public Builder timeAndHorizontalScalingConfigs(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndHorizontalScalingConfig... timeAndHorizontalScalingConfigs) {
            return timeAndHorizontalScalingConfigs(List.of(timeAndHorizontalScalingConfigs));
        }
        @CustomType.Setter
        public Builder timeAndVerticalScalingConfigs(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs) {
            if (timeAndVerticalScalingConfigs == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail", "timeAndVerticalScalingConfigs");
            }
            this.timeAndVerticalScalingConfigs = timeAndVerticalScalingConfigs;
            return this;
        }
        public Builder timeAndVerticalScalingConfigs(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetailTimeAndVerticalScalingConfig... timeAndVerticalScalingConfigs) {
            return timeAndVerticalScalingConfigs(List.of(timeAndVerticalScalingConfigs));
        }
        public GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail build() {
            final var _resultValue = new GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScheduleDetail();
            _resultValue.scheduleType = scheduleType;
            _resultValue.timeAndHorizontalScalingConfigs = timeAndHorizontalScalingConfigs;
            _resultValue.timeAndVerticalScalingConfigs = timeAndVerticalScalingConfigs;
            return _resultValue;
        }
    }
}
