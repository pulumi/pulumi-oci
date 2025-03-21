// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTaskScheduleSchedule {
    /**
     * @return Value in cron format.
     * 
     */
    private String expression;
    /**
     * @return Schedule misfire retry policy.
     * 
     */
    private String misfirePolicy;
    /**
     * @return Recurring interval in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P14D (not P2W). The value must be at least 5 minutes (PT5M) and at most 3 weeks (P21D or PT30240M).
     * 
     */
    private String recurringInterval;
    /**
     * @return Number of times (0-based) to execute until auto-stop. Default value -1 will execute indefinitely. Value 0 will execute once.
     * 
     */
    private Integer repeatCount;
    /**
     * @return Time zone, by default UTC.
     * 
     */
    private String timeZone;
    /**
     * @return Schedule type discriminator.
     * 
     */
    private String type;

    private GetNamespaceScheduledTaskScheduleSchedule() {}
    /**
     * @return Value in cron format.
     * 
     */
    public String expression() {
        return this.expression;
    }
    /**
     * @return Schedule misfire retry policy.
     * 
     */
    public String misfirePolicy() {
        return this.misfirePolicy;
    }
    /**
     * @return Recurring interval in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P14D (not P2W). The value must be at least 5 minutes (PT5M) and at most 3 weeks (P21D or PT30240M).
     * 
     */
    public String recurringInterval() {
        return this.recurringInterval;
    }
    /**
     * @return Number of times (0-based) to execute until auto-stop. Default value -1 will execute indefinitely. Value 0 will execute once.
     * 
     */
    public Integer repeatCount() {
        return this.repeatCount;
    }
    /**
     * @return Time zone, by default UTC.
     * 
     */
    public String timeZone() {
        return this.timeZone;
    }
    /**
     * @return Schedule type discriminator.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTaskScheduleSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String expression;
        private String misfirePolicy;
        private String recurringInterval;
        private Integer repeatCount;
        private String timeZone;
        private String type;
        public Builder() {}
        public Builder(GetNamespaceScheduledTaskScheduleSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.expression = defaults.expression;
    	      this.misfirePolicy = defaults.misfirePolicy;
    	      this.recurringInterval = defaults.recurringInterval;
    	      this.repeatCount = defaults.repeatCount;
    	      this.timeZone = defaults.timeZone;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder expression(String expression) {
            if (expression == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskScheduleSchedule", "expression");
            }
            this.expression = expression;
            return this;
        }
        @CustomType.Setter
        public Builder misfirePolicy(String misfirePolicy) {
            if (misfirePolicy == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskScheduleSchedule", "misfirePolicy");
            }
            this.misfirePolicy = misfirePolicy;
            return this;
        }
        @CustomType.Setter
        public Builder recurringInterval(String recurringInterval) {
            if (recurringInterval == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskScheduleSchedule", "recurringInterval");
            }
            this.recurringInterval = recurringInterval;
            return this;
        }
        @CustomType.Setter
        public Builder repeatCount(Integer repeatCount) {
            if (repeatCount == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskScheduleSchedule", "repeatCount");
            }
            this.repeatCount = repeatCount;
            return this;
        }
        @CustomType.Setter
        public Builder timeZone(String timeZone) {
            if (timeZone == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskScheduleSchedule", "timeZone");
            }
            this.timeZone = timeZone;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTaskScheduleSchedule", "type");
            }
            this.type = type;
            return this;
        }
        public GetNamespaceScheduledTaskScheduleSchedule build() {
            final var _resultValue = new GetNamespaceScheduledTaskScheduleSchedule();
            _resultValue.expression = expression;
            _resultValue.misfirePolicy = misfirePolicy;
            _resultValue.recurringInterval = recurringInterval;
            _resultValue.repeatCount = repeatCount;
            _resultValue.timeZone = timeZone;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
