// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MonitoringTemplateAlarmConditionCondition {
    /**
     * @return (Updatable) The human-readable content of the delivered alarm notification. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.
     * 
     */
    private @Nullable String body;
    /**
     * @return (Updatable) The Monitoring Query Language (MQL) expression to evaluate for the alarm.
     * 
     */
    private String query;
    /**
     * @return (Updatable) Severity - Critical/Warning
     * 
     */
    private String severity;
    /**
     * @return (Updatable) Whether the note need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    private @Nullable Boolean shouldAppendNote;
    /**
     * @return (Updatable) Whether the URL need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    private @Nullable Boolean shouldAppendUrl;
    /**
     * @return (Updatable) The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;.
     * 
     */
    private @Nullable String triggerDelay;

    private MonitoringTemplateAlarmConditionCondition() {}
    /**
     * @return (Updatable) The human-readable content of the delivered alarm notification. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.
     * 
     */
    public Optional<String> body() {
        return Optional.ofNullable(this.body);
    }
    /**
     * @return (Updatable) The Monitoring Query Language (MQL) expression to evaluate for the alarm.
     * 
     */
    public String query() {
        return this.query;
    }
    /**
     * @return (Updatable) Severity - Critical/Warning
     * 
     */
    public String severity() {
        return this.severity;
    }
    /**
     * @return (Updatable) Whether the note need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    public Optional<Boolean> shouldAppendNote() {
        return Optional.ofNullable(this.shouldAppendNote);
    }
    /**
     * @return (Updatable) Whether the URL need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    public Optional<Boolean> shouldAppendUrl() {
        return Optional.ofNullable(this.shouldAppendUrl);
    }
    /**
     * @return (Updatable) The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;.
     * 
     */
    public Optional<String> triggerDelay() {
        return Optional.ofNullable(this.triggerDelay);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MonitoringTemplateAlarmConditionCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String body;
        private String query;
        private String severity;
        private @Nullable Boolean shouldAppendNote;
        private @Nullable Boolean shouldAppendUrl;
        private @Nullable String triggerDelay;
        public Builder() {}
        public Builder(MonitoringTemplateAlarmConditionCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.body = defaults.body;
    	      this.query = defaults.query;
    	      this.severity = defaults.severity;
    	      this.shouldAppendNote = defaults.shouldAppendNote;
    	      this.shouldAppendUrl = defaults.shouldAppendUrl;
    	      this.triggerDelay = defaults.triggerDelay;
        }

        @CustomType.Setter
        public Builder body(@Nullable String body) {

            this.body = body;
            return this;
        }
        @CustomType.Setter
        public Builder query(String query) {
            if (query == null) {
              throw new MissingRequiredPropertyException("MonitoringTemplateAlarmConditionCondition", "query");
            }
            this.query = query;
            return this;
        }
        @CustomType.Setter
        public Builder severity(String severity) {
            if (severity == null) {
              throw new MissingRequiredPropertyException("MonitoringTemplateAlarmConditionCondition", "severity");
            }
            this.severity = severity;
            return this;
        }
        @CustomType.Setter
        public Builder shouldAppendNote(@Nullable Boolean shouldAppendNote) {

            this.shouldAppendNote = shouldAppendNote;
            return this;
        }
        @CustomType.Setter
        public Builder shouldAppendUrl(@Nullable Boolean shouldAppendUrl) {

            this.shouldAppendUrl = shouldAppendUrl;
            return this;
        }
        @CustomType.Setter
        public Builder triggerDelay(@Nullable String triggerDelay) {

            this.triggerDelay = triggerDelay;
            return this;
        }
        public MonitoringTemplateAlarmConditionCondition build() {
            final var _resultValue = new MonitoringTemplateAlarmConditionCondition();
            _resultValue.body = body;
            _resultValue.query = query;
            _resultValue.severity = severity;
            _resultValue.shouldAppendNote = shouldAppendNote;
            _resultValue.shouldAppendUrl = shouldAppendUrl;
            _resultValue.triggerDelay = triggerDelay;
            return _resultValue;
        }
    }
}
