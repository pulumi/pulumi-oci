// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AtCustomerCccUpgradeScheduleEvent {
    /**
     * @return (Updatable) A description of the Compute Cloud{@literal @}Customer upgrade schedule time block.
     * 
     */
    private String description;
    /**
     * @return Generated name associated with the event.
     * 
     */
    private @Nullable String name;
    /**
     * @return (Updatable) The duration of this block of time. The duration must be specified and be of the ISO-8601 format for durations.
     * 
     */
    private String scheduleEventDuration;
    /**
     * @return (Updatable) Frequency of recurrence of schedule block. When this field is not included, the event is assumed to be a one time occurrence. The frequency field is strictly parsed and must conform to RFC-5545 formatting for recurrences.
     * 
     */
    private @Nullable String scheduleEventRecurrences;
    /**
     * @return (Updatable) The date and time when the Compute Cloud{@literal @}Customer upgrade schedule event starts, inclusive. An RFC3339 formatted UTC datetime string. For an event with recurrences, this is the date that a recurrence can start being applied.
     * 
     */
    private String timeStart;

    private AtCustomerCccUpgradeScheduleEvent() {}
    /**
     * @return (Updatable) A description of the Compute Cloud{@literal @}Customer upgrade schedule time block.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Generated name associated with the event.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return (Updatable) The duration of this block of time. The duration must be specified and be of the ISO-8601 format for durations.
     * 
     */
    public String scheduleEventDuration() {
        return this.scheduleEventDuration;
    }
    /**
     * @return (Updatable) Frequency of recurrence of schedule block. When this field is not included, the event is assumed to be a one time occurrence. The frequency field is strictly parsed and must conform to RFC-5545 formatting for recurrences.
     * 
     */
    public Optional<String> scheduleEventRecurrences() {
        return Optional.ofNullable(this.scheduleEventRecurrences);
    }
    /**
     * @return (Updatable) The date and time when the Compute Cloud{@literal @}Customer upgrade schedule event starts, inclusive. An RFC3339 formatted UTC datetime string. For an event with recurrences, this is the date that a recurrence can start being applied.
     * 
     */
    public String timeStart() {
        return this.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AtCustomerCccUpgradeScheduleEvent defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private @Nullable String name;
        private String scheduleEventDuration;
        private @Nullable String scheduleEventRecurrences;
        private String timeStart;
        public Builder() {}
        public Builder(AtCustomerCccUpgradeScheduleEvent defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.name = defaults.name;
    	      this.scheduleEventDuration = defaults.scheduleEventDuration;
    	      this.scheduleEventRecurrences = defaults.scheduleEventRecurrences;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("AtCustomerCccUpgradeScheduleEvent", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder scheduleEventDuration(String scheduleEventDuration) {
            if (scheduleEventDuration == null) {
              throw new MissingRequiredPropertyException("AtCustomerCccUpgradeScheduleEvent", "scheduleEventDuration");
            }
            this.scheduleEventDuration = scheduleEventDuration;
            return this;
        }
        @CustomType.Setter
        public Builder scheduleEventRecurrences(@Nullable String scheduleEventRecurrences) {

            this.scheduleEventRecurrences = scheduleEventRecurrences;
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(String timeStart) {
            if (timeStart == null) {
              throw new MissingRequiredPropertyException("AtCustomerCccUpgradeScheduleEvent", "timeStart");
            }
            this.timeStart = timeStart;
            return this;
        }
        public AtCustomerCccUpgradeScheduleEvent build() {
            final var _resultValue = new AtCustomerCccUpgradeScheduleEvent();
            _resultValue.description = description;
            _resultValue.name = name;
            _resultValue.scheduleEventDuration = scheduleEventDuration;
            _resultValue.scheduleEventRecurrences = scheduleEventRecurrences;
            _resultValue.timeStart = timeStart;
            return _resultValue;
        }
    }
}
