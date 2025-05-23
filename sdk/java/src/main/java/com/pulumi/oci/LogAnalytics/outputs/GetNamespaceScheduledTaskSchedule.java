// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTaskScheduleSchedule;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTaskSchedule {
    private List<GetNamespaceScheduledTaskScheduleSchedule> schedules;

    private GetNamespaceScheduledTaskSchedule() {}
    public List<GetNamespaceScheduledTaskScheduleSchedule> schedules() {
        return this.schedules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTaskSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNamespaceScheduledTaskScheduleSchedule> schedules;
        public Builder() {}
        public Builder(GetNamespaceScheduledTaskSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.schedules = defaults.schedules;
        }

        @CustomType.Setter
        public Builder schedules(List<GetNamespaceScheduledTaskScheduleSchedule> schedules) {
            if (schedules == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskSchedule", "schedules");
            }
            this.schedules = schedules;
            return this;
        }
        public Builder schedules(GetNamespaceScheduledTaskScheduleSchedule... schedules) {
            return schedules(List.of(schedules));
        }
        public GetNamespaceScheduledTaskSchedule build() {
            final var _resultValue = new GetNamespaceScheduledTaskSchedule();
            _resultValue.schedules = schedules;
            return _resultValue;
        }
    }
}
