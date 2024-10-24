// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs;
import com.pulumi.oci.Database.inputs.AutonomousVmClusterMaintenanceWindowDetailMonthArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousVmClusterMaintenanceWindowDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousVmClusterMaintenanceWindowDetailArgs Empty = new AutonomousVmClusterMaintenanceWindowDetailArgs();

    @Import(name="customActionTimeoutInMins")
    private @Nullable Output<Integer> customActionTimeoutInMins;

    public Optional<Output<Integer>> customActionTimeoutInMins() {
        return Optional.ofNullable(this.customActionTimeoutInMins);
    }

    /**
     * (Updatable) Days during the week when maintenance should be performed.
     * 
     */
    @Import(name="daysOfWeeks")
    private @Nullable Output<List<AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs>> daysOfWeeks;

    /**
     * @return (Updatable) Days during the week when maintenance should be performed.
     * 
     */
    public Optional<Output<List<AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs>>> daysOfWeeks() {
        return Optional.ofNullable(this.daysOfWeeks);
    }

    /**
     * (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
     * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
     * 
     */
    @Import(name="hoursOfDays")
    private @Nullable Output<List<Integer>> hoursOfDays;

    /**
     * @return (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
     * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
     * 
     */
    public Optional<Output<List<Integer>>> hoursOfDays() {
        return Optional.ofNullable(this.hoursOfDays);
    }

    @Import(name="isCustomActionTimeoutEnabled")
    private @Nullable Output<Boolean> isCustomActionTimeoutEnabled;

    public Optional<Output<Boolean>> isCustomActionTimeoutEnabled() {
        return Optional.ofNullable(this.isCustomActionTimeoutEnabled);
    }

    @Import(name="isMonthlyPatchingEnabled")
    private @Nullable Output<Boolean> isMonthlyPatchingEnabled;

    public Optional<Output<Boolean>> isMonthlyPatchingEnabled() {
        return Optional.ofNullable(this.isMonthlyPatchingEnabled);
    }

    /**
     * (Updatable) Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
     * 
     */
    @Import(name="leadTimeInWeeks")
    private @Nullable Output<Integer> leadTimeInWeeks;

    /**
     * @return (Updatable) Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
     * 
     */
    public Optional<Output<Integer>> leadTimeInWeeks() {
        return Optional.ofNullable(this.leadTimeInWeeks);
    }

    /**
     * (Updatable) Months during the year when maintenance should be performed.
     * 
     */
    @Import(name="months")
    private @Nullable Output<List<AutonomousVmClusterMaintenanceWindowDetailMonthArgs>> months;

    /**
     * @return (Updatable) Months during the year when maintenance should be performed.
     * 
     */
    public Optional<Output<List<AutonomousVmClusterMaintenanceWindowDetailMonthArgs>>> months() {
        return Optional.ofNullable(this.months);
    }

    /**
     * (Updatable) Cloud Exadata infrastructure node patching method, either &#34;ROLLING&#34; or &#34;NONROLLING&#34;. Default value is ROLLING.
     * 
     * *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
     * 
     */
    @Import(name="patchingMode")
    private @Nullable Output<String> patchingMode;

    /**
     * @return (Updatable) Cloud Exadata infrastructure node patching method, either &#34;ROLLING&#34; or &#34;NONROLLING&#34;. Default value is ROLLING.
     * 
     * *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
     * 
     */
    public Optional<Output<String>> patchingMode() {
        return Optional.ofNullable(this.patchingMode);
    }

    /**
     * (Updatable) The maintenance window scheduling preference.
     * 
     */
    @Import(name="preference")
    private @Nullable Output<String> preference;

    /**
     * @return (Updatable) The maintenance window scheduling preference.
     * 
     */
    public Optional<Output<String>> preference() {
        return Optional.ofNullable(this.preference);
    }

    /**
     * (Updatable) If true, skips the release update (RU) for the quarter. You cannot skip two consecutive quarters. An RU skip request will only be honoured if the current version of the Autonomous Container Database is supported for current quarter.
     * 
     */
    @Import(name="skipRus")
    private @Nullable Output<List<Boolean>> skipRus;

    /**
     * @return (Updatable) If true, skips the release update (RU) for the quarter. You cannot skip two consecutive quarters. An RU skip request will only be honoured if the current version of the Autonomous Container Database is supported for current quarter.
     * 
     */
    public Optional<Output<List<Boolean>>> skipRus() {
        return Optional.ofNullable(this.skipRus);
    }

    /**
     * (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
     * 
     */
    @Import(name="weeksOfMonths")
    private @Nullable Output<List<Integer>> weeksOfMonths;

    /**
     * @return (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
     * 
     */
    public Optional<Output<List<Integer>>> weeksOfMonths() {
        return Optional.ofNullable(this.weeksOfMonths);
    }

    private AutonomousVmClusterMaintenanceWindowDetailArgs() {}

    private AutonomousVmClusterMaintenanceWindowDetailArgs(AutonomousVmClusterMaintenanceWindowDetailArgs $) {
        this.customActionTimeoutInMins = $.customActionTimeoutInMins;
        this.daysOfWeeks = $.daysOfWeeks;
        this.hoursOfDays = $.hoursOfDays;
        this.isCustomActionTimeoutEnabled = $.isCustomActionTimeoutEnabled;
        this.isMonthlyPatchingEnabled = $.isMonthlyPatchingEnabled;
        this.leadTimeInWeeks = $.leadTimeInWeeks;
        this.months = $.months;
        this.patchingMode = $.patchingMode;
        this.preference = $.preference;
        this.skipRus = $.skipRus;
        this.weeksOfMonths = $.weeksOfMonths;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousVmClusterMaintenanceWindowDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousVmClusterMaintenanceWindowDetailArgs $;

        public Builder() {
            $ = new AutonomousVmClusterMaintenanceWindowDetailArgs();
        }

        public Builder(AutonomousVmClusterMaintenanceWindowDetailArgs defaults) {
            $ = new AutonomousVmClusterMaintenanceWindowDetailArgs(Objects.requireNonNull(defaults));
        }

        public Builder customActionTimeoutInMins(@Nullable Output<Integer> customActionTimeoutInMins) {
            $.customActionTimeoutInMins = customActionTimeoutInMins;
            return this;
        }

        public Builder customActionTimeoutInMins(Integer customActionTimeoutInMins) {
            return customActionTimeoutInMins(Output.of(customActionTimeoutInMins));
        }

        /**
         * @param daysOfWeeks (Updatable) Days during the week when maintenance should be performed.
         * 
         * @return builder
         * 
         */
        public Builder daysOfWeeks(@Nullable Output<List<AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs>> daysOfWeeks) {
            $.daysOfWeeks = daysOfWeeks;
            return this;
        }

        /**
         * @param daysOfWeeks (Updatable) Days during the week when maintenance should be performed.
         * 
         * @return builder
         * 
         */
        public Builder daysOfWeeks(List<AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs> daysOfWeeks) {
            return daysOfWeeks(Output.of(daysOfWeeks));
        }

        /**
         * @param daysOfWeeks (Updatable) Days during the week when maintenance should be performed.
         * 
         * @return builder
         * 
         */
        public Builder daysOfWeeks(AutonomousVmClusterMaintenanceWindowDetailDaysOfWeekArgs... daysOfWeeks) {
            return daysOfWeeks(List.of(daysOfWeeks));
        }

        /**
         * @param hoursOfDays (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
         * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
         * 
         * @return builder
         * 
         */
        public Builder hoursOfDays(@Nullable Output<List<Integer>> hoursOfDays) {
            $.hoursOfDays = hoursOfDays;
            return this;
        }

        /**
         * @param hoursOfDays (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
         * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
         * 
         * @return builder
         * 
         */
        public Builder hoursOfDays(List<Integer> hoursOfDays) {
            return hoursOfDays(Output.of(hoursOfDays));
        }

        /**
         * @param hoursOfDays (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
         * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
         * 
         * @return builder
         * 
         */
        public Builder hoursOfDays(Integer... hoursOfDays) {
            return hoursOfDays(List.of(hoursOfDays));
        }

        public Builder isCustomActionTimeoutEnabled(@Nullable Output<Boolean> isCustomActionTimeoutEnabled) {
            $.isCustomActionTimeoutEnabled = isCustomActionTimeoutEnabled;
            return this;
        }

        public Builder isCustomActionTimeoutEnabled(Boolean isCustomActionTimeoutEnabled) {
            return isCustomActionTimeoutEnabled(Output.of(isCustomActionTimeoutEnabled));
        }

        public Builder isMonthlyPatchingEnabled(@Nullable Output<Boolean> isMonthlyPatchingEnabled) {
            $.isMonthlyPatchingEnabled = isMonthlyPatchingEnabled;
            return this;
        }

        public Builder isMonthlyPatchingEnabled(Boolean isMonthlyPatchingEnabled) {
            return isMonthlyPatchingEnabled(Output.of(isMonthlyPatchingEnabled));
        }

        /**
         * @param leadTimeInWeeks (Updatable) Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
         * 
         * @return builder
         * 
         */
        public Builder leadTimeInWeeks(@Nullable Output<Integer> leadTimeInWeeks) {
            $.leadTimeInWeeks = leadTimeInWeeks;
            return this;
        }

        /**
         * @param leadTimeInWeeks (Updatable) Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
         * 
         * @return builder
         * 
         */
        public Builder leadTimeInWeeks(Integer leadTimeInWeeks) {
            return leadTimeInWeeks(Output.of(leadTimeInWeeks));
        }

        /**
         * @param months (Updatable) Months during the year when maintenance should be performed.
         * 
         * @return builder
         * 
         */
        public Builder months(@Nullable Output<List<AutonomousVmClusterMaintenanceWindowDetailMonthArgs>> months) {
            $.months = months;
            return this;
        }

        /**
         * @param months (Updatable) Months during the year when maintenance should be performed.
         * 
         * @return builder
         * 
         */
        public Builder months(List<AutonomousVmClusterMaintenanceWindowDetailMonthArgs> months) {
            return months(Output.of(months));
        }

        /**
         * @param months (Updatable) Months during the year when maintenance should be performed.
         * 
         * @return builder
         * 
         */
        public Builder months(AutonomousVmClusterMaintenanceWindowDetailMonthArgs... months) {
            return months(List.of(months));
        }

        /**
         * @param patchingMode (Updatable) Cloud Exadata infrastructure node patching method, either &#34;ROLLING&#34; or &#34;NONROLLING&#34;. Default value is ROLLING.
         * 
         * *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
         * 
         * @return builder
         * 
         */
        public Builder patchingMode(@Nullable Output<String> patchingMode) {
            $.patchingMode = patchingMode;
            return this;
        }

        /**
         * @param patchingMode (Updatable) Cloud Exadata infrastructure node patching method, either &#34;ROLLING&#34; or &#34;NONROLLING&#34;. Default value is ROLLING.
         * 
         * *IMPORTANT*: Non-rolling infrastructure patching involves system down time. See [Oracle-Managed Infrastructure Maintenance Updates](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/examaintenance.htm#Oracle) for more information.
         * 
         * @return builder
         * 
         */
        public Builder patchingMode(String patchingMode) {
            return patchingMode(Output.of(patchingMode));
        }

        /**
         * @param preference (Updatable) The maintenance window scheduling preference.
         * 
         * @return builder
         * 
         */
        public Builder preference(@Nullable Output<String> preference) {
            $.preference = preference;
            return this;
        }

        /**
         * @param preference (Updatable) The maintenance window scheduling preference.
         * 
         * @return builder
         * 
         */
        public Builder preference(String preference) {
            return preference(Output.of(preference));
        }

        /**
         * @param skipRus (Updatable) If true, skips the release update (RU) for the quarter. You cannot skip two consecutive quarters. An RU skip request will only be honoured if the current version of the Autonomous Container Database is supported for current quarter.
         * 
         * @return builder
         * 
         */
        public Builder skipRus(@Nullable Output<List<Boolean>> skipRus) {
            $.skipRus = skipRus;
            return this;
        }

        /**
         * @param skipRus (Updatable) If true, skips the release update (RU) for the quarter. You cannot skip two consecutive quarters. An RU skip request will only be honoured if the current version of the Autonomous Container Database is supported for current quarter.
         * 
         * @return builder
         * 
         */
        public Builder skipRus(List<Boolean> skipRus) {
            return skipRus(Output.of(skipRus));
        }

        /**
         * @param skipRus (Updatable) If true, skips the release update (RU) for the quarter. You cannot skip two consecutive quarters. An RU skip request will only be honoured if the current version of the Autonomous Container Database is supported for current quarter.
         * 
         * @return builder
         * 
         */
        public Builder skipRus(Boolean... skipRus) {
            return skipRus(List.of(skipRus));
        }

        /**
         * @param weeksOfMonths (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
         * 
         * @return builder
         * 
         */
        public Builder weeksOfMonths(@Nullable Output<List<Integer>> weeksOfMonths) {
            $.weeksOfMonths = weeksOfMonths;
            return this;
        }

        /**
         * @param weeksOfMonths (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
         * 
         * @return builder
         * 
         */
        public Builder weeksOfMonths(List<Integer> weeksOfMonths) {
            return weeksOfMonths(Output.of(weeksOfMonths));
        }

        /**
         * @param weeksOfMonths (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
         * 
         * @return builder
         * 
         */
        public Builder weeksOfMonths(Integer... weeksOfMonths) {
            return weeksOfMonths(List.of(weeksOfMonths));
        }

        public AutonomousVmClusterMaintenanceWindowDetailArgs build() {
            return $;
        }
    }

}
