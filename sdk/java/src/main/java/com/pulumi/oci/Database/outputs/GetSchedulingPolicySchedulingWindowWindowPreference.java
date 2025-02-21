// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetSchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek;
import com.pulumi.oci.Database.outputs.GetSchedulingPolicySchedulingWindowWindowPreferenceMonth;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSchedulingPolicySchedulingWindowWindowPreference {
    /**
     * @return Days during the week when scheduling window should be performed.
     * 
     */
    private List<GetSchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks;
    /**
     * @return Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     */
    private Integer duration;
    /**
     * @return Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    private Boolean isEnforcedDuration;
    /**
     * @return Months during the year when scheduled window should be performed.
     * 
     */
    private List<GetSchedulingPolicySchedulingWindowWindowPreferenceMonth> months;
    /**
     * @return The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
     * 
     */
    private String startTime;
    /**
     * @return Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
     * 
     */
    private List<Integer> weeksOfMonths;

    private GetSchedulingPolicySchedulingWindowWindowPreference() {}
    /**
     * @return Days during the week when scheduling window should be performed.
     * 
     */
    public List<GetSchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks() {
        return this.daysOfWeeks;
    }
    /**
     * @return Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     */
    public Integer duration() {
        return this.duration;
    }
    /**
     * @return Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    public Boolean isEnforcedDuration() {
        return this.isEnforcedDuration;
    }
    /**
     * @return Months during the year when scheduled window should be performed.
     * 
     */
    public List<GetSchedulingPolicySchedulingWindowWindowPreferenceMonth> months() {
        return this.months;
    }
    /**
     * @return The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
     * 
     */
    public String startTime() {
        return this.startTime;
    }
    /**
     * @return Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
     * 
     */
    public List<Integer> weeksOfMonths() {
        return this.weeksOfMonths;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulingPolicySchedulingWindowWindowPreference defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks;
        private Integer duration;
        private Boolean isEnforcedDuration;
        private List<GetSchedulingPolicySchedulingWindowWindowPreferenceMonth> months;
        private String startTime;
        private List<Integer> weeksOfMonths;
        public Builder() {}
        public Builder(GetSchedulingPolicySchedulingWindowWindowPreference defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.daysOfWeeks = defaults.daysOfWeeks;
    	      this.duration = defaults.duration;
    	      this.isEnforcedDuration = defaults.isEnforcedDuration;
    	      this.months = defaults.months;
    	      this.startTime = defaults.startTime;
    	      this.weeksOfMonths = defaults.weeksOfMonths;
        }

        @CustomType.Setter
        public Builder daysOfWeeks(List<GetSchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks) {
            if (daysOfWeeks == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowWindowPreference", "daysOfWeeks");
            }
            this.daysOfWeeks = daysOfWeeks;
            return this;
        }
        public Builder daysOfWeeks(GetSchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek... daysOfWeeks) {
            return daysOfWeeks(List.of(daysOfWeeks));
        }
        @CustomType.Setter
        public Builder duration(Integer duration) {
            if (duration == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowWindowPreference", "duration");
            }
            this.duration = duration;
            return this;
        }
        @CustomType.Setter
        public Builder isEnforcedDuration(Boolean isEnforcedDuration) {
            if (isEnforcedDuration == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowWindowPreference", "isEnforcedDuration");
            }
            this.isEnforcedDuration = isEnforcedDuration;
            return this;
        }
        @CustomType.Setter
        public Builder months(List<GetSchedulingPolicySchedulingWindowWindowPreferenceMonth> months) {
            if (months == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowWindowPreference", "months");
            }
            this.months = months;
            return this;
        }
        public Builder months(GetSchedulingPolicySchedulingWindowWindowPreferenceMonth... months) {
            return months(List.of(months));
        }
        @CustomType.Setter
        public Builder startTime(String startTime) {
            if (startTime == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowWindowPreference", "startTime");
            }
            this.startTime = startTime;
            return this;
        }
        @CustomType.Setter
        public Builder weeksOfMonths(List<Integer> weeksOfMonths) {
            if (weeksOfMonths == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowWindowPreference", "weeksOfMonths");
            }
            this.weeksOfMonths = weeksOfMonths;
            return this;
        }
        public Builder weeksOfMonths(Integer... weeksOfMonths) {
            return weeksOfMonths(List.of(weeksOfMonths));
        }
        public GetSchedulingPolicySchedulingWindowWindowPreference build() {
            final var _resultValue = new GetSchedulingPolicySchedulingWindowWindowPreference();
            _resultValue.daysOfWeeks = daysOfWeeks;
            _resultValue.duration = duration;
            _resultValue.isEnforcedDuration = isEnforcedDuration;
            _resultValue.months = months;
            _resultValue.startTime = startTime;
            _resultValue.weeksOfMonths = weeksOfMonths;
            return _resultValue;
        }
    }
}
