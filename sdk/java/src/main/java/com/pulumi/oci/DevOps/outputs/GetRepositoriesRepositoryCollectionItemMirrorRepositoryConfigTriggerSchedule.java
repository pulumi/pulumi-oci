// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRepositoriesRepositoryCollectionItemMirrorRepositoryConfigTriggerSchedule {
    /**
     * @return Valid if type is CUSTOM. Following RFC 5545 recurrence rules, we can specify starting time, occurrence frequency, and interval size. Example for frequency could be DAILY/WEEKLY/HOURLY or any RFC 5545 supported frequency, which is followed by start time of this window. You can control the start time with BYHOUR, BYMINUTE and BYSECONDS. It is followed by the interval size.
     * 
     */
    private String customSchedule;
    /**
     * @return Different types of trigger schedule: NONE - No automated synchronization schedule. DEFAULT - Trigger schedule is every 30 minutes. CUSTOM - Custom triggering schedule.
     * 
     */
    private String scheduleType;

    private GetRepositoriesRepositoryCollectionItemMirrorRepositoryConfigTriggerSchedule() {}
    /**
     * @return Valid if type is CUSTOM. Following RFC 5545 recurrence rules, we can specify starting time, occurrence frequency, and interval size. Example for frequency could be DAILY/WEEKLY/HOURLY or any RFC 5545 supported frequency, which is followed by start time of this window. You can control the start time with BYHOUR, BYMINUTE and BYSECONDS. It is followed by the interval size.
     * 
     */
    public String customSchedule() {
        return this.customSchedule;
    }
    /**
     * @return Different types of trigger schedule: NONE - No automated synchronization schedule. DEFAULT - Trigger schedule is every 30 minutes. CUSTOM - Custom triggering schedule.
     * 
     */
    public String scheduleType() {
        return this.scheduleType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoriesRepositoryCollectionItemMirrorRepositoryConfigTriggerSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String customSchedule;
        private String scheduleType;
        public Builder() {}
        public Builder(GetRepositoriesRepositoryCollectionItemMirrorRepositoryConfigTriggerSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.customSchedule = defaults.customSchedule;
    	      this.scheduleType = defaults.scheduleType;
        }

        @CustomType.Setter
        public Builder customSchedule(String customSchedule) {
            this.customSchedule = Objects.requireNonNull(customSchedule);
            return this;
        }
        @CustomType.Setter
        public Builder scheduleType(String scheduleType) {
            this.scheduleType = Objects.requireNonNull(scheduleType);
            return this;
        }
        public GetRepositoriesRepositoryCollectionItemMirrorRepositoryConfigTriggerSchedule build() {
            final var o = new GetRepositoriesRepositoryCollectionItemMirrorRepositoryConfigTriggerSchedule();
            o.customSchedule = customSchedule;
            o.scheduleType = scheduleType;
            return o;
        }
    }
}