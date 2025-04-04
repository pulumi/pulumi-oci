// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitoringTemplateAlarmConditionCondition {
    /**
     * @return The human-readable content of the delivered alarm notification. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.
     * 
     */
    private String body;
    /**
     * @return The Monitoring Query Language (MQL) expression to evaluate for the alarm.
     * 
     */
    private String query;
    /**
     * @return Severity - Critical/Warning
     * 
     */
    private String severity;
    /**
     * @return Whether the note need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    private Boolean shouldAppendNote;
    /**
     * @return Whether the URL need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    private Boolean shouldAppendUrl;
    /**
     * @return The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;.
     * 
     */
    private String triggerDelay;

    private GetMonitoringTemplateAlarmConditionCondition() {}
    /**
     * @return The human-readable content of the delivered alarm notification. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.
     * 
     */
    public String body() {
        return this.body;
    }
    /**
     * @return The Monitoring Query Language (MQL) expression to evaluate for the alarm.
     * 
     */
    public String query() {
        return this.query;
    }
    /**
     * @return Severity - Critical/Warning
     * 
     */
    public String severity() {
        return this.severity;
    }
    /**
     * @return Whether the note need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    public Boolean shouldAppendNote() {
        return this.shouldAppendNote;
    }
    /**
     * @return Whether the URL need to add into bottom of the body for mapping the alarms information with template or not.
     * 
     */
    public Boolean shouldAppendUrl() {
        return this.shouldAppendUrl;
    }
    /**
     * @return The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;.
     * 
     */
    public String triggerDelay() {
        return this.triggerDelay;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoringTemplateAlarmConditionCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String body;
        private String query;
        private String severity;
        private Boolean shouldAppendNote;
        private Boolean shouldAppendUrl;
        private String triggerDelay;
        public Builder() {}
        public Builder(GetMonitoringTemplateAlarmConditionCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.body = defaults.body;
    	      this.query = defaults.query;
    	      this.severity = defaults.severity;
    	      this.shouldAppendNote = defaults.shouldAppendNote;
    	      this.shouldAppendUrl = defaults.shouldAppendUrl;
    	      this.triggerDelay = defaults.triggerDelay;
        }

        @CustomType.Setter
        public Builder body(String body) {
            if (body == null) {
              throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionCondition", "body");
            }
            this.body = body;
            return this;
        }
        @CustomType.Setter
        public Builder query(String query) {
            if (query == null) {
              throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionCondition", "query");
            }
            this.query = query;
            return this;
        }
        @CustomType.Setter
        public Builder severity(String severity) {
            if (severity == null) {
              throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionCondition", "severity");
            }
            this.severity = severity;
            return this;
        }
        @CustomType.Setter
        public Builder shouldAppendNote(Boolean shouldAppendNote) {
            if (shouldAppendNote == null) {
              throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionCondition", "shouldAppendNote");
            }
            this.shouldAppendNote = shouldAppendNote;
            return this;
        }
        @CustomType.Setter
        public Builder shouldAppendUrl(Boolean shouldAppendUrl) {
            if (shouldAppendUrl == null) {
              throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionCondition", "shouldAppendUrl");
            }
            this.shouldAppendUrl = shouldAppendUrl;
            return this;
        }
        @CustomType.Setter
        public Builder triggerDelay(String triggerDelay) {
            if (triggerDelay == null) {
              throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionCondition", "triggerDelay");
            }
            this.triggerDelay = triggerDelay;
            return this;
        }
        public GetMonitoringTemplateAlarmConditionCondition build() {
            final var _resultValue = new GetMonitoringTemplateAlarmConditionCondition();
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
