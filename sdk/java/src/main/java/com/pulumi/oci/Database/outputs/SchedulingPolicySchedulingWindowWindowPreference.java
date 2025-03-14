// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek;
import com.pulumi.oci.Database.outputs.SchedulingPolicySchedulingWindowWindowPreferenceMonth;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class SchedulingPolicySchedulingWindowWindowPreference {
    /**
     * @return (Updatable) Days during the week when scheduling window should be performed.
     * 
     */
    private List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks;
    /**
     * @return (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     */
    private Integer duration;
    /**
     * @return (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    private Boolean isEnforcedDuration;
    /**
     * @return (Updatable) Months during the year when scheduled window should be performed.
     * 
     */
    private List<SchedulingPolicySchedulingWindowWindowPreferenceMonth> months;
    /**
     * @return (Updatable) The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
     * 
     */
    private String startTime;
    /**
     * @return (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private List<Integer> weeksOfMonths;

    private SchedulingPolicySchedulingWindowWindowPreference() {}
    /**
     * @return (Updatable) Days during the week when scheduling window should be performed.
     * 
     */
    public List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks() {
        return this.daysOfWeeks;
    }
    /**
     * @return (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     */
    public Integer duration() {
        return this.duration;
    }
    /**
     * @return (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    public Boolean isEnforcedDuration() {
        return this.isEnforcedDuration;
    }
    /**
     * @return (Updatable) Months during the year when scheduled window should be performed.
     * 
     */
    public List<SchedulingPolicySchedulingWindowWindowPreferenceMonth> months() {
        return this.months;
    }
    /**
     * @return (Updatable) The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
     * 
     */
    public String startTime() {
        return this.startTime;
    }
    /**
     * @return (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public List<Integer> weeksOfMonths() {
        return this.weeksOfMonths;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SchedulingPolicySchedulingWindowWindowPreference defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks;
        private Integer duration;
        private Boolean isEnforcedDuration;
        private List<SchedulingPolicySchedulingWindowWindowPreferenceMonth> months;
        private String startTime;
        private List<Integer> weeksOfMonths;
        public Builder() {}
        public Builder(SchedulingPolicySchedulingWindowWindowPreference defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.daysOfWeeks = defaults.daysOfWeeks;
    	      this.duration = defaults.duration;
    	      this.isEnforcedDuration = defaults.isEnforcedDuration;
    	      this.months = defaults.months;
    	      this.startTime = defaults.startTime;
    	      this.weeksOfMonths = defaults.weeksOfMonths;
        }

        @CustomType.Setter
        public Builder daysOfWeeks(List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek> daysOfWeeks) {
            if (daysOfWeeks == null) {
              throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreference", "daysOfWeeks");
            }
            this.daysOfWeeks = daysOfWeeks;
            return this;
        }
        public Builder daysOfWeeks(SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeek... daysOfWeeks) {
            return daysOfWeeks(List.of(daysOfWeeks));
        }
        @CustomType.Setter
        public Builder duration(Integer duration) {
            if (duration == null) {
              throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreference", "duration");
            }
            this.duration = duration;
            return this;
        }
        @CustomType.Setter
        public Builder isEnforcedDuration(Boolean isEnforcedDuration) {
            if (isEnforcedDuration == null) {
              throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreference", "isEnforcedDuration");
            }
            this.isEnforcedDuration = isEnforcedDuration;
            return this;
        }
        @CustomType.Setter
        public Builder months(List<SchedulingPolicySchedulingWindowWindowPreferenceMonth> months) {
            if (months == null) {
              throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreference", "months");
            }
            this.months = months;
            return this;
        }
        public Builder months(SchedulingPolicySchedulingWindowWindowPreferenceMonth... months) {
            return months(List.of(months));
        }
        @CustomType.Setter
        public Builder startTime(String startTime) {
            if (startTime == null) {
              throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreference", "startTime");
            }
            this.startTime = startTime;
            return this;
        }
        @CustomType.Setter
        public Builder weeksOfMonths(List<Integer> weeksOfMonths) {
            if (weeksOfMonths == null) {
              throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreference", "weeksOfMonths");
            }
            this.weeksOfMonths = weeksOfMonths;
            return this;
        }
        public Builder weeksOfMonths(Integer... weeksOfMonths) {
            return weeksOfMonths(List.of(weeksOfMonths));
        }
        public SchedulingPolicySchedulingWindowWindowPreference build() {
            final var _resultValue = new SchedulingPolicySchedulingWindowWindowPreference();
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
