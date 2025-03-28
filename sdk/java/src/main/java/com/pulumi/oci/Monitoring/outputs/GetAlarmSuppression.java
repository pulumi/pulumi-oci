// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAlarmSuppression {
    /**
     * @return Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T01:02:29.600Z`
     * 
     */
    private String timeSuppressFrom;
    /**
     * @return The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T02:02:29.600Z`
     * 
     */
    private String timeSuppressUntil;

    private GetAlarmSuppression() {}
    /**
     * @return Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T01:02:29.600Z`
     * 
     */
    public String timeSuppressFrom() {
        return this.timeSuppressFrom;
    }
    /**
     * @return The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T02:02:29.600Z`
     * 
     */
    public String timeSuppressUntil() {
        return this.timeSuppressUntil;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlarmSuppression defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String timeSuppressFrom;
        private String timeSuppressUntil;
        public Builder() {}
        public Builder(GetAlarmSuppression defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.timeSuppressFrom = defaults.timeSuppressFrom;
    	      this.timeSuppressUntil = defaults.timeSuppressUntil;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppression", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder timeSuppressFrom(String timeSuppressFrom) {
            if (timeSuppressFrom == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppression", "timeSuppressFrom");
            }
            this.timeSuppressFrom = timeSuppressFrom;
            return this;
        }
        @CustomType.Setter
        public Builder timeSuppressUntil(String timeSuppressUntil) {
            if (timeSuppressUntil == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppression", "timeSuppressUntil");
            }
            this.timeSuppressUntil = timeSuppressUntil;
            return this;
        }
        public GetAlarmSuppression build() {
            final var _resultValue = new GetAlarmSuppression();
            _resultValue.description = description;
            _resultValue.timeSuppressFrom = timeSuppressFrom;
            _resultValue.timeSuppressUntil = timeSuppressUntil;
            return _resultValue;
        }
    }
}
