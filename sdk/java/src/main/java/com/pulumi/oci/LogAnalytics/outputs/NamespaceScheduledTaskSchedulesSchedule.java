// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class NamespaceScheduledTaskSchedulesSchedule {
    /**
     * @return Value in cron format.
     * 
     */
    private @Nullable String expression;
    /**
     * @return Schedule misfire retry policy.
     * 
     */
    private @Nullable String misfirePolicy;
    /**
     * @return Recurring interval in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P14D (not P2W). The value must be at least 5 minutes (PT5M) and at most 3 weeks (P21D or PT30240M).
     * 
     */
    private @Nullable String recurringInterval;
    /**
     * @return Number of times (0-based) to execute until auto-stop. Default value -1 will execute indefinitely. Value 0 will execute once.
     * 
     */
    private @Nullable Integer repeatCount;
    /**
     * @return Time zone, by default UTC.
     * 
     */
    private @Nullable String timeZone;
    /**
     * @return Schedule type discriminator.
     * 
     */
    private String type;

    private NamespaceScheduledTaskSchedulesSchedule() {}
    /**
     * @return Value in cron format.
     * 
     */
    public Optional<String> expression() {
        return Optional.ofNullable(this.expression);
    }
    /**
     * @return Schedule misfire retry policy.
     * 
     */
    public Optional<String> misfirePolicy() {
        return Optional.ofNullable(this.misfirePolicy);
    }
    /**
     * @return Recurring interval in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P14D (not P2W). The value must be at least 5 minutes (PT5M) and at most 3 weeks (P21D or PT30240M).
     * 
     */
    public Optional<String> recurringInterval() {
        return Optional.ofNullable(this.recurringInterval);
    }
    /**
     * @return Number of times (0-based) to execute until auto-stop. Default value -1 will execute indefinitely. Value 0 will execute once.
     * 
     */
    public Optional<Integer> repeatCount() {
        return Optional.ofNullable(this.repeatCount);
    }
    /**
     * @return Time zone, by default UTC.
     * 
     */
    public Optional<String> timeZone() {
        return Optional.ofNullable(this.timeZone);
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

    public static Builder builder(NamespaceScheduledTaskSchedulesSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String expression;
        private @Nullable String misfirePolicy;
        private @Nullable String recurringInterval;
        private @Nullable Integer repeatCount;
        private @Nullable String timeZone;
        private String type;
        public Builder() {}
        public Builder(NamespaceScheduledTaskSchedulesSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.expression = defaults.expression;
    	      this.misfirePolicy = defaults.misfirePolicy;
    	      this.recurringInterval = defaults.recurringInterval;
    	      this.repeatCount = defaults.repeatCount;
    	      this.timeZone = defaults.timeZone;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder expression(@Nullable String expression) {

            this.expression = expression;
            return this;
        }
        @CustomType.Setter
        public Builder misfirePolicy(@Nullable String misfirePolicy) {

            this.misfirePolicy = misfirePolicy;
            return this;
        }
        @CustomType.Setter
        public Builder recurringInterval(@Nullable String recurringInterval) {

            this.recurringInterval = recurringInterval;
            return this;
        }
        @CustomType.Setter
        public Builder repeatCount(@Nullable Integer repeatCount) {

            this.repeatCount = repeatCount;
            return this;
        }
        @CustomType.Setter
        public Builder timeZone(@Nullable String timeZone) {

            this.timeZone = timeZone;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("NamespaceScheduledTaskSchedulesSchedule", "type");
            }
            this.type = type;
            return this;
        }
        public NamespaceScheduledTaskSchedulesSchedule build() {
            final var _resultValue = new NamespaceScheduledTaskSchedulesSchedule();
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
