// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAlarmSuppressionSuppressionCondition {
    /**
     * @return Type of suppression condition.
     * 
     */
    private String conditionType;
    /**
     * @return Duration of the recurring suppression. Specified as a string in ISO 8601 format. Minimum: `PT1M` (1 minute). Maximum: `PT24H` (24 hours).
     * 
     */
    private String suppressionDuration;
    /**
     * @return Frequency and start time of the recurring suppression. The format follows [the iCalendar specification (RFC 5545, section 3.3.10)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10). Supported rule parts:
     * * `FREQ`: Frequency of the recurring suppression: `WEEKLY` or `DAILY` only.
     * * `BYDAY`: Comma separated days. Use with weekly suppressions only. Supported values: `MO`, `TU`, `WE`, `TH`, `FR`, `SA` ,`SU`.
     * * `BYHOUR`, `BYMINUTE`, `BYSECOND`: Start time in UTC, after `timeSuppressFrom` value. Default is 00:00:00 UTC after `timeSuppressFrom`.
     * 
     */
    private String suppressionRecurrence;

    private GetAlarmSuppressionSuppressionCondition() {}
    /**
     * @return Type of suppression condition.
     * 
     */
    public String conditionType() {
        return this.conditionType;
    }
    /**
     * @return Duration of the recurring suppression. Specified as a string in ISO 8601 format. Minimum: `PT1M` (1 minute). Maximum: `PT24H` (24 hours).
     * 
     */
    public String suppressionDuration() {
        return this.suppressionDuration;
    }
    /**
     * @return Frequency and start time of the recurring suppression. The format follows [the iCalendar specification (RFC 5545, section 3.3.10)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10). Supported rule parts:
     * * `FREQ`: Frequency of the recurring suppression: `WEEKLY` or `DAILY` only.
     * * `BYDAY`: Comma separated days. Use with weekly suppressions only. Supported values: `MO`, `TU`, `WE`, `TH`, `FR`, `SA` ,`SU`.
     * * `BYHOUR`, `BYMINUTE`, `BYSECOND`: Start time in UTC, after `timeSuppressFrom` value. Default is 00:00:00 UTC after `timeSuppressFrom`.
     * 
     */
    public String suppressionRecurrence() {
        return this.suppressionRecurrence;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlarmSuppressionSuppressionCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String conditionType;
        private String suppressionDuration;
        private String suppressionRecurrence;
        public Builder() {}
        public Builder(GetAlarmSuppressionSuppressionCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.conditionType = defaults.conditionType;
    	      this.suppressionDuration = defaults.suppressionDuration;
    	      this.suppressionRecurrence = defaults.suppressionRecurrence;
        }

        @CustomType.Setter
        public Builder conditionType(String conditionType) {
            if (conditionType == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionSuppressionCondition", "conditionType");
            }
            this.conditionType = conditionType;
            return this;
        }
        @CustomType.Setter
        public Builder suppressionDuration(String suppressionDuration) {
            if (suppressionDuration == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionSuppressionCondition", "suppressionDuration");
            }
            this.suppressionDuration = suppressionDuration;
            return this;
        }
        @CustomType.Setter
        public Builder suppressionRecurrence(String suppressionRecurrence) {
            if (suppressionRecurrence == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionSuppressionCondition", "suppressionRecurrence");
            }
            this.suppressionRecurrence = suppressionRecurrence;
            return this;
        }
        public GetAlarmSuppressionSuppressionCondition build() {
            final var _resultValue = new GetAlarmSuppressionSuppressionCondition();
            _resultValue.conditionType = conditionType;
            _resultValue.suppressionDuration = suppressionDuration;
            _resultValue.suppressionRecurrence = suppressionRecurrence;
            return _resultValue;
        }
    }
}
