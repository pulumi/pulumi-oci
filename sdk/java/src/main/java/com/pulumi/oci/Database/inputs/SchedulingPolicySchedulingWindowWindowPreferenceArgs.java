// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeekArgs;
import com.pulumi.oci.Database.inputs.SchedulingPolicySchedulingWindowWindowPreferenceMonthArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class SchedulingPolicySchedulingWindowWindowPreferenceArgs extends com.pulumi.resources.ResourceArgs {

    public static final SchedulingPolicySchedulingWindowWindowPreferenceArgs Empty = new SchedulingPolicySchedulingWindowWindowPreferenceArgs();

    /**
     * (Updatable) Days during the week when scheduling window should be performed.
     * 
     */
    @Import(name="daysOfWeeks", required=true)
    private Output<List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeekArgs>> daysOfWeeks;

    /**
     * @return (Updatable) Days during the week when scheduling window should be performed.
     * 
     */
    public Output<List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeekArgs>> daysOfWeeks() {
        return this.daysOfWeeks;
    }

    /**
     * (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     */
    @Import(name="duration", required=true)
    private Output<Integer> duration;

    /**
     * @return (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     */
    public Output<Integer> duration() {
        return this.duration;
    }

    /**
     * (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    @Import(name="isEnforcedDuration", required=true)
    private Output<Boolean> isEnforcedDuration;

    /**
     * @return (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    public Output<Boolean> isEnforcedDuration() {
        return this.isEnforcedDuration;
    }

    /**
     * (Updatable) Months during the year when scheduled window should be performed.
     * 
     */
    @Import(name="months", required=true)
    private Output<List<SchedulingPolicySchedulingWindowWindowPreferenceMonthArgs>> months;

    /**
     * @return (Updatable) Months during the year when scheduled window should be performed.
     * 
     */
    public Output<List<SchedulingPolicySchedulingWindowWindowPreferenceMonthArgs>> months() {
        return this.months;
    }

    /**
     * (Updatable) The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
     * 
     */
    @Import(name="startTime", required=true)
    private Output<String> startTime;

    /**
     * @return (Updatable) The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
     * 
     */
    public Output<String> startTime() {
        return this.startTime;
    }

    /**
     * (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="weeksOfMonths", required=true)
    private Output<List<Integer>> weeksOfMonths;

    /**
     * @return (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<Integer>> weeksOfMonths() {
        return this.weeksOfMonths;
    }

    private SchedulingPolicySchedulingWindowWindowPreferenceArgs() {}

    private SchedulingPolicySchedulingWindowWindowPreferenceArgs(SchedulingPolicySchedulingWindowWindowPreferenceArgs $) {
        this.daysOfWeeks = $.daysOfWeeks;
        this.duration = $.duration;
        this.isEnforcedDuration = $.isEnforcedDuration;
        this.months = $.months;
        this.startTime = $.startTime;
        this.weeksOfMonths = $.weeksOfMonths;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulingPolicySchedulingWindowWindowPreferenceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulingPolicySchedulingWindowWindowPreferenceArgs $;

        public Builder() {
            $ = new SchedulingPolicySchedulingWindowWindowPreferenceArgs();
        }

        public Builder(SchedulingPolicySchedulingWindowWindowPreferenceArgs defaults) {
            $ = new SchedulingPolicySchedulingWindowWindowPreferenceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param daysOfWeeks (Updatable) Days during the week when scheduling window should be performed.
         * 
         * @return builder
         * 
         */
        public Builder daysOfWeeks(Output<List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeekArgs>> daysOfWeeks) {
            $.daysOfWeeks = daysOfWeeks;
            return this;
        }

        /**
         * @param daysOfWeeks (Updatable) Days during the week when scheduling window should be performed.
         * 
         * @return builder
         * 
         */
        public Builder daysOfWeeks(List<SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeekArgs> daysOfWeeks) {
            return daysOfWeeks(Output.of(daysOfWeeks));
        }

        /**
         * @param daysOfWeeks (Updatable) Days during the week when scheduling window should be performed.
         * 
         * @return builder
         * 
         */
        public Builder daysOfWeeks(SchedulingPolicySchedulingWindowWindowPreferenceDaysOfWeekArgs... daysOfWeeks) {
            return daysOfWeeks(List.of(daysOfWeeks));
        }

        /**
         * @param duration (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
         * 
         * @return builder
         * 
         */
        public Builder duration(Output<Integer> duration) {
            $.duration = duration;
            return this;
        }

        /**
         * @param duration (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
         * 
         * @return builder
         * 
         */
        public Builder duration(Integer duration) {
            return duration(Output.of(duration));
        }

        /**
         * @param isEnforcedDuration (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
         * 
         * @return builder
         * 
         */
        public Builder isEnforcedDuration(Output<Boolean> isEnforcedDuration) {
            $.isEnforcedDuration = isEnforcedDuration;
            return this;
        }

        /**
         * @param isEnforcedDuration (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
         * 
         * @return builder
         * 
         */
        public Builder isEnforcedDuration(Boolean isEnforcedDuration) {
            return isEnforcedDuration(Output.of(isEnforcedDuration));
        }

        /**
         * @param months (Updatable) Months during the year when scheduled window should be performed.
         * 
         * @return builder
         * 
         */
        public Builder months(Output<List<SchedulingPolicySchedulingWindowWindowPreferenceMonthArgs>> months) {
            $.months = months;
            return this;
        }

        /**
         * @param months (Updatable) Months during the year when scheduled window should be performed.
         * 
         * @return builder
         * 
         */
        public Builder months(List<SchedulingPolicySchedulingWindowWindowPreferenceMonthArgs> months) {
            return months(Output.of(months));
        }

        /**
         * @param months (Updatable) Months during the year when scheduled window should be performed.
         * 
         * @return builder
         * 
         */
        public Builder months(SchedulingPolicySchedulingWindowWindowPreferenceMonthArgs... months) {
            return months(List.of(months));
        }

        /**
         * @param startTime (Updatable) The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
         * 
         * @return builder
         * 
         */
        public Builder startTime(Output<String> startTime) {
            $.startTime = startTime;
            return this;
        }

        /**
         * @param startTime (Updatable) The scheduling window start time. The value must use the ISO-8601 format &#34;hh:mm&#34;.
         * 
         * @return builder
         * 
         */
        public Builder startTime(String startTime) {
            return startTime(Output.of(startTime));
        }

        /**
         * @param weeksOfMonths (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder weeksOfMonths(Output<List<Integer>> weeksOfMonths) {
            $.weeksOfMonths = weeksOfMonths;
            return this;
        }

        /**
         * @param weeksOfMonths (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder weeksOfMonths(List<Integer> weeksOfMonths) {
            return weeksOfMonths(Output.of(weeksOfMonths));
        }

        /**
         * @param weeksOfMonths (Updatable) Weeks during the month when scheduled window should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow scheduling window during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Scheduling window cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and startTime parameters to allow you to specify specific days of the week and hours that scheduled window will be performed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder weeksOfMonths(Integer... weeksOfMonths) {
            return weeksOfMonths(List.of(weeksOfMonths));
        }

        public SchedulingPolicySchedulingWindowWindowPreferenceArgs build() {
            if ($.daysOfWeeks == null) {
                throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreferenceArgs", "daysOfWeeks");
            }
            if ($.duration == null) {
                throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreferenceArgs", "duration");
            }
            if ($.isEnforcedDuration == null) {
                throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreferenceArgs", "isEnforcedDuration");
            }
            if ($.months == null) {
                throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreferenceArgs", "months");
            }
            if ($.startTime == null) {
                throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreferenceArgs", "startTime");
            }
            if ($.weeksOfMonths == null) {
                throw new MissingRequiredPropertyException("SchedulingPolicySchedulingWindowWindowPreferenceArgs", "weeksOfMonths");
            }
            return $;
        }
    }

}
