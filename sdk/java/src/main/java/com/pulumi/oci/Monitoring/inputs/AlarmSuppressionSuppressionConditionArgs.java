// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class AlarmSuppressionSuppressionConditionArgs extends com.pulumi.resources.ResourceArgs {

    public static final AlarmSuppressionSuppressionConditionArgs Empty = new AlarmSuppressionSuppressionConditionArgs();

    /**
     * Type of suppression condition.
     * 
     */
    @Import(name="conditionType", required=true)
    private Output<String> conditionType;

    /**
     * @return Type of suppression condition.
     * 
     */
    public Output<String> conditionType() {
        return this.conditionType;
    }

    /**
     * Duration of the recurring suppression. Specified as a string in ISO 8601 format. Minimum: `PT1M` (1 minute). Maximum: `PT24H` (24 hours).
     * 
     */
    @Import(name="suppressionDuration", required=true)
    private Output<String> suppressionDuration;

    /**
     * @return Duration of the recurring suppression. Specified as a string in ISO 8601 format. Minimum: `PT1M` (1 minute). Maximum: `PT24H` (24 hours).
     * 
     */
    public Output<String> suppressionDuration() {
        return this.suppressionDuration;
    }

    /**
     * Frequency and start time of the recurring suppression. The format follows [the iCalendar specification (RFC 5545, section 3.3.10)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10). Supported rule parts:
     * * `FREQ`: Frequency of the recurring suppression: `WEEKLY` or `DAILY` only.
     * * `BYDAY`: Comma separated days. Use with weekly suppressions only. Supported values: `MO`, `TU`, `WE`, `TH`, `FR`, `SA` ,`SU`.
     * * `BYHOUR`, `BYMINUTE`, `BYSECOND`: Start time in UTC, after `timeSuppressFrom` value. Default is 00:00:00 UTC after `timeSuppressFrom`.
     * 
     */
    @Import(name="suppressionRecurrence", required=true)
    private Output<String> suppressionRecurrence;

    /**
     * @return Frequency and start time of the recurring suppression. The format follows [the iCalendar specification (RFC 5545, section 3.3.10)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10). Supported rule parts:
     * * `FREQ`: Frequency of the recurring suppression: `WEEKLY` or `DAILY` only.
     * * `BYDAY`: Comma separated days. Use with weekly suppressions only. Supported values: `MO`, `TU`, `WE`, `TH`, `FR`, `SA` ,`SU`.
     * * `BYHOUR`, `BYMINUTE`, `BYSECOND`: Start time in UTC, after `timeSuppressFrom` value. Default is 00:00:00 UTC after `timeSuppressFrom`.
     * 
     */
    public Output<String> suppressionRecurrence() {
        return this.suppressionRecurrence;
    }

    private AlarmSuppressionSuppressionConditionArgs() {}

    private AlarmSuppressionSuppressionConditionArgs(AlarmSuppressionSuppressionConditionArgs $) {
        this.conditionType = $.conditionType;
        this.suppressionDuration = $.suppressionDuration;
        this.suppressionRecurrence = $.suppressionRecurrence;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AlarmSuppressionSuppressionConditionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AlarmSuppressionSuppressionConditionArgs $;

        public Builder() {
            $ = new AlarmSuppressionSuppressionConditionArgs();
        }

        public Builder(AlarmSuppressionSuppressionConditionArgs defaults) {
            $ = new AlarmSuppressionSuppressionConditionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param conditionType Type of suppression condition.
         * 
         * @return builder
         * 
         */
        public Builder conditionType(Output<String> conditionType) {
            $.conditionType = conditionType;
            return this;
        }

        /**
         * @param conditionType Type of suppression condition.
         * 
         * @return builder
         * 
         */
        public Builder conditionType(String conditionType) {
            return conditionType(Output.of(conditionType));
        }

        /**
         * @param suppressionDuration Duration of the recurring suppression. Specified as a string in ISO 8601 format. Minimum: `PT1M` (1 minute). Maximum: `PT24H` (24 hours).
         * 
         * @return builder
         * 
         */
        public Builder suppressionDuration(Output<String> suppressionDuration) {
            $.suppressionDuration = suppressionDuration;
            return this;
        }

        /**
         * @param suppressionDuration Duration of the recurring suppression. Specified as a string in ISO 8601 format. Minimum: `PT1M` (1 minute). Maximum: `PT24H` (24 hours).
         * 
         * @return builder
         * 
         */
        public Builder suppressionDuration(String suppressionDuration) {
            return suppressionDuration(Output.of(suppressionDuration));
        }

        /**
         * @param suppressionRecurrence Frequency and start time of the recurring suppression. The format follows [the iCalendar specification (RFC 5545, section 3.3.10)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10). Supported rule parts:
         * * `FREQ`: Frequency of the recurring suppression: `WEEKLY` or `DAILY` only.
         * * `BYDAY`: Comma separated days. Use with weekly suppressions only. Supported values: `MO`, `TU`, `WE`, `TH`, `FR`, `SA` ,`SU`.
         * * `BYHOUR`, `BYMINUTE`, `BYSECOND`: Start time in UTC, after `timeSuppressFrom` value. Default is 00:00:00 UTC after `timeSuppressFrom`.
         * 
         * @return builder
         * 
         */
        public Builder suppressionRecurrence(Output<String> suppressionRecurrence) {
            $.suppressionRecurrence = suppressionRecurrence;
            return this;
        }

        /**
         * @param suppressionRecurrence Frequency and start time of the recurring suppression. The format follows [the iCalendar specification (RFC 5545, section 3.3.10)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10). Supported rule parts:
         * * `FREQ`: Frequency of the recurring suppression: `WEEKLY` or `DAILY` only.
         * * `BYDAY`: Comma separated days. Use with weekly suppressions only. Supported values: `MO`, `TU`, `WE`, `TH`, `FR`, `SA` ,`SU`.
         * * `BYHOUR`, `BYMINUTE`, `BYSECOND`: Start time in UTC, after `timeSuppressFrom` value. Default is 00:00:00 UTC after `timeSuppressFrom`.
         * 
         * @return builder
         * 
         */
        public Builder suppressionRecurrence(String suppressionRecurrence) {
            return suppressionRecurrence(Output.of(suppressionRecurrence));
        }

        public AlarmSuppressionSuppressionConditionArgs build() {
            if ($.conditionType == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionSuppressionConditionArgs", "conditionType");
            }
            if ($.suppressionDuration == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionSuppressionConditionArgs", "suppressionDuration");
            }
            if ($.suppressionRecurrence == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionSuppressionConditionArgs", "suppressionRecurrence");
            }
            return $;
        }
    }

}
