// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndHorizontalScalingConfig;
import com.pulumi.oci.BigDataService.outputs.AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfig;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutoScalingConfigurationPolicyDetailsScheduleDetail {
    /**
     * @return (Updatable) The type of schedule.
     * 
     */
    private @Nullable String scheduleType;
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs;
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs;

    private AutoScalingConfigurationPolicyDetailsScheduleDetail() {}
    /**
     * @return (Updatable) The type of schedule.
     * 
     */
    public Optional<String> scheduleType() {
        return Optional.ofNullable(this.scheduleType);
    }
    /**
     * @return (Updatable)
     * 
     */
    public List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs() {
        return this.timeAndHorizontalScalingConfigs == null ? List.of() : this.timeAndHorizontalScalingConfigs;
    }
    /**
     * @return (Updatable)
     * 
     */
    public List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs() {
        return this.timeAndVerticalScalingConfigs == null ? List.of() : this.timeAndVerticalScalingConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutoScalingConfigurationPolicyDetailsScheduleDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String scheduleType;
        private @Nullable List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs;
        private @Nullable List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs;
        public Builder() {}
        public Builder(AutoScalingConfigurationPolicyDetailsScheduleDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.scheduleType = defaults.scheduleType;
    	      this.timeAndHorizontalScalingConfigs = defaults.timeAndHorizontalScalingConfigs;
    	      this.timeAndVerticalScalingConfigs = defaults.timeAndVerticalScalingConfigs;
        }

        @CustomType.Setter
        public Builder scheduleType(@Nullable String scheduleType) {
            this.scheduleType = scheduleType;
            return this;
        }
        @CustomType.Setter
        public Builder timeAndHorizontalScalingConfigs(@Nullable List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndHorizontalScalingConfig> timeAndHorizontalScalingConfigs) {
            this.timeAndHorizontalScalingConfigs = timeAndHorizontalScalingConfigs;
            return this;
        }
        public Builder timeAndHorizontalScalingConfigs(AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndHorizontalScalingConfig... timeAndHorizontalScalingConfigs) {
            return timeAndHorizontalScalingConfigs(List.of(timeAndHorizontalScalingConfigs));
        }
        @CustomType.Setter
        public Builder timeAndVerticalScalingConfigs(@Nullable List<AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfig> timeAndVerticalScalingConfigs) {
            this.timeAndVerticalScalingConfigs = timeAndVerticalScalingConfigs;
            return this;
        }
        public Builder timeAndVerticalScalingConfigs(AutoScalingConfigurationPolicyDetailsScheduleDetailTimeAndVerticalScalingConfig... timeAndVerticalScalingConfigs) {
            return timeAndVerticalScalingConfigs(List.of(timeAndVerticalScalingConfigs));
        }
        public AutoScalingConfigurationPolicyDetailsScheduleDetail build() {
            final var o = new AutoScalingConfigurationPolicyDetailsScheduleDetail();
            o.scheduleType = scheduleType;
            o.timeAndHorizontalScalingConfigs = timeAndHorizontalScalingConfigs;
            o.timeAndVerticalScalingConfigs = timeAndVerticalScalingConfigs;
            return o;
        }
    }
}