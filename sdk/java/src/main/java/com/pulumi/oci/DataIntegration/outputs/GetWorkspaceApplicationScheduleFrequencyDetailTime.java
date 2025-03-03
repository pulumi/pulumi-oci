// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationScheduleFrequencyDetailTime {
    /**
     * @return The hour value.
     * 
     */
    private Integer hour;
    /**
     * @return The minute value.
     * 
     */
    private Integer minute;
    /**
     * @return The second value.
     * 
     */
    private Integer second;

    private GetWorkspaceApplicationScheduleFrequencyDetailTime() {}
    /**
     * @return The hour value.
     * 
     */
    public Integer hour() {
        return this.hour;
    }
    /**
     * @return The minute value.
     * 
     */
    public Integer minute() {
        return this.minute;
    }
    /**
     * @return The second value.
     * 
     */
    public Integer second() {
        return this.second;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationScheduleFrequencyDetailTime defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer hour;
        private Integer minute;
        private Integer second;
        public Builder() {}
        public Builder(GetWorkspaceApplicationScheduleFrequencyDetailTime defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hour = defaults.hour;
    	      this.minute = defaults.minute;
    	      this.second = defaults.second;
        }

        @CustomType.Setter
        public Builder hour(Integer hour) {
            if (hour == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationScheduleFrequencyDetailTime", "hour");
            }
            this.hour = hour;
            return this;
        }
        @CustomType.Setter
        public Builder minute(Integer minute) {
            if (minute == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationScheduleFrequencyDetailTime", "minute");
            }
            this.minute = minute;
            return this;
        }
        @CustomType.Setter
        public Builder second(Integer second) {
            if (second == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationScheduleFrequencyDetailTime", "second");
            }
            this.second = second;
            return this;
        }
        public GetWorkspaceApplicationScheduleFrequencyDetailTime build() {
            final var _resultValue = new GetWorkspaceApplicationScheduleFrequencyDetailTime();
            _resultValue.hour = hour;
            _resultValue.minute = minute;
            _resultValue.second = second;
            return _resultValue;
        }
    }
}
