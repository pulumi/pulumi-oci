// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.NamespaceScheduledTaskSchedulesSchedule;
import java.util.List;
import java.util.Objects;

@CustomType
public final class NamespaceScheduledTaskSchedules {
    private final List<NamespaceScheduledTaskSchedulesSchedule> schedules;

    @CustomType.Constructor
    private NamespaceScheduledTaskSchedules(@CustomType.Parameter("schedules") List<NamespaceScheduledTaskSchedulesSchedule> schedules) {
        this.schedules = schedules;
    }

    public List<NamespaceScheduledTaskSchedulesSchedule> schedules() {
        return this.schedules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NamespaceScheduledTaskSchedules defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<NamespaceScheduledTaskSchedulesSchedule> schedules;

        public Builder() {
    	      // Empty
        }

        public Builder(NamespaceScheduledTaskSchedules defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.schedules = defaults.schedules;
        }

        public Builder schedules(List<NamespaceScheduledTaskSchedulesSchedule> schedules) {
            this.schedules = Objects.requireNonNull(schedules);
            return this;
        }
        public Builder schedules(NamespaceScheduledTaskSchedulesSchedule... schedules) {
            return schedules(List.of(schedules));
        }        public NamespaceScheduledTaskSchedules build() {
            return new NamespaceScheduledTaskSchedules(schedules);
        }
    }
}
