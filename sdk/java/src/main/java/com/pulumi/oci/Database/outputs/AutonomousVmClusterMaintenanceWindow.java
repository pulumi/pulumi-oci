// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.AutonomousVmClusterMaintenanceWindowDaysOfWeek;
import com.pulumi.oci.Database.outputs.AutonomousVmClusterMaintenanceWindowMonth;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousVmClusterMaintenanceWindow {
    /**
     * @return (Updatable) Days during the week when maintenance should be performed.
     * 
     */
    private final @Nullable List<AutonomousVmClusterMaintenanceWindowDaysOfWeek> daysOfWeeks;
    /**
     * @return (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
     * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
     * 
     */
    private final @Nullable List<Integer> hoursOfDays;
    /**
     * @return (Updatable) Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
     * 
     */
    private final @Nullable Integer leadTimeInWeeks;
    /**
     * @return (Updatable) Months during the year when maintenance should be performed.
     * 
     */
    private final @Nullable List<AutonomousVmClusterMaintenanceWindowMonth> months;
    /**
     * @return (Updatable) The maintenance window scheduling preference.
     * 
     */
    private final @Nullable String preference;
    /**
     * @return (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
     * 
     */
    private final @Nullable List<Integer> weeksOfMonths;

    @CustomType.Constructor
    private AutonomousVmClusterMaintenanceWindow(
        @CustomType.Parameter("daysOfWeeks") @Nullable List<AutonomousVmClusterMaintenanceWindowDaysOfWeek> daysOfWeeks,
        @CustomType.Parameter("hoursOfDays") @Nullable List<Integer> hoursOfDays,
        @CustomType.Parameter("leadTimeInWeeks") @Nullable Integer leadTimeInWeeks,
        @CustomType.Parameter("months") @Nullable List<AutonomousVmClusterMaintenanceWindowMonth> months,
        @CustomType.Parameter("preference") @Nullable String preference,
        @CustomType.Parameter("weeksOfMonths") @Nullable List<Integer> weeksOfMonths) {
        this.daysOfWeeks = daysOfWeeks;
        this.hoursOfDays = hoursOfDays;
        this.leadTimeInWeeks = leadTimeInWeeks;
        this.months = months;
        this.preference = preference;
        this.weeksOfMonths = weeksOfMonths;
    }

    /**
     * @return (Updatable) Days during the week when maintenance should be performed.
     * 
     */
    public List<AutonomousVmClusterMaintenanceWindowDaysOfWeek> daysOfWeeks() {
        return this.daysOfWeeks == null ? List.of() : this.daysOfWeeks;
    }
    /**
     * @return (Updatable) The window of hours during the day when maintenance should be performed. The window is a 4 hour slot. Valid values are
     * * 0 - represents time slot 0:00 - 3:59 UTC - 4 - represents time slot 4:00 - 7:59 UTC - 8 - represents time slot 8:00 - 11:59 UTC - 12 - represents time slot 12:00 - 15:59 UTC - 16 - represents time slot 16:00 - 19:59 UTC - 20 - represents time slot 20:00 - 23:59 UTC
     * 
     */
    public List<Integer> hoursOfDays() {
        return this.hoursOfDays == null ? List.of() : this.hoursOfDays;
    }
    /**
     * @return (Updatable) Lead time window allows user to set a lead time to prepare for a down time. The lead time is in weeks and valid value is between 1 to 4.
     * 
     */
    public Optional<Integer> leadTimeInWeeks() {
        return Optional.ofNullable(this.leadTimeInWeeks);
    }
    /**
     * @return (Updatable) Months during the year when maintenance should be performed.
     * 
     */
    public List<AutonomousVmClusterMaintenanceWindowMonth> months() {
        return this.months == null ? List.of() : this.months;
    }
    /**
     * @return (Updatable) The maintenance window scheduling preference.
     * 
     */
    public Optional<String> preference() {
        return Optional.ofNullable(this.preference);
    }
    /**
     * @return (Updatable) Weeks during the month when maintenance should be performed. Weeks start on the 1st, 8th, 15th, and 22nd days of the month, and have a duration of 7 days. Weeks start and end based on calendar dates, not days of the week. For example, to allow maintenance during the 2nd week of the month (from the 8th day to the 14th day of the month), use the value 2. Maintenance cannot be scheduled for the fifth week of months that contain more than 28 days. Note that this parameter works in conjunction with the  daysOfWeek and hoursOfDay parameters to allow you to specify specific days of the week and hours that maintenance will be performed.
     * 
     */
    public List<Integer> weeksOfMonths() {
        return this.weeksOfMonths == null ? List.of() : this.weeksOfMonths;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousVmClusterMaintenanceWindow defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<AutonomousVmClusterMaintenanceWindowDaysOfWeek> daysOfWeeks;
        private @Nullable List<Integer> hoursOfDays;
        private @Nullable Integer leadTimeInWeeks;
        private @Nullable List<AutonomousVmClusterMaintenanceWindowMonth> months;
        private @Nullable String preference;
        private @Nullable List<Integer> weeksOfMonths;

        public Builder() {
    	      // Empty
        }

        public Builder(AutonomousVmClusterMaintenanceWindow defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.daysOfWeeks = defaults.daysOfWeeks;
    	      this.hoursOfDays = defaults.hoursOfDays;
    	      this.leadTimeInWeeks = defaults.leadTimeInWeeks;
    	      this.months = defaults.months;
    	      this.preference = defaults.preference;
    	      this.weeksOfMonths = defaults.weeksOfMonths;
        }

        public Builder daysOfWeeks(@Nullable List<AutonomousVmClusterMaintenanceWindowDaysOfWeek> daysOfWeeks) {
            this.daysOfWeeks = daysOfWeeks;
            return this;
        }
        public Builder daysOfWeeks(AutonomousVmClusterMaintenanceWindowDaysOfWeek... daysOfWeeks) {
            return daysOfWeeks(List.of(daysOfWeeks));
        }
        public Builder hoursOfDays(@Nullable List<Integer> hoursOfDays) {
            this.hoursOfDays = hoursOfDays;
            return this;
        }
        public Builder hoursOfDays(Integer... hoursOfDays) {
            return hoursOfDays(List.of(hoursOfDays));
        }
        public Builder leadTimeInWeeks(@Nullable Integer leadTimeInWeeks) {
            this.leadTimeInWeeks = leadTimeInWeeks;
            return this;
        }
        public Builder months(@Nullable List<AutonomousVmClusterMaintenanceWindowMonth> months) {
            this.months = months;
            return this;
        }
        public Builder months(AutonomousVmClusterMaintenanceWindowMonth... months) {
            return months(List.of(months));
        }
        public Builder preference(@Nullable String preference) {
            this.preference = preference;
            return this;
        }
        public Builder weeksOfMonths(@Nullable List<Integer> weeksOfMonths) {
            this.weeksOfMonths = weeksOfMonths;
            return this;
        }
        public Builder weeksOfMonths(Integer... weeksOfMonths) {
            return weeksOfMonths(List.of(weeksOfMonths));
        }        public AutonomousVmClusterMaintenanceWindow build() {
            return new AutonomousVmClusterMaintenanceWindow(daysOfWeeks, hoursOfDays, leadTimeInWeeks, months, preference, weeksOfMonths);
        }
    }
}
