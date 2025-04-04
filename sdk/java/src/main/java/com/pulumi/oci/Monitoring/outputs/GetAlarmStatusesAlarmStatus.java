// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Monitoring.outputs.GetAlarmStatusesAlarmStatusSuppression;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAlarmStatusesAlarmStatus {
    /**
     * @return Customizable alarm summary (`alarmSummary` [alarm message parameter](https://docs.cloud.oracle.com/iaas/Content/Monitoring/alarm-message-format.htm)). Optionally include [dynamic variables](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/update-alarm-dynamic-variables.htm). The alarm summary appears within the body of the alarm message and in responses to  [ListAlarmStatus](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmStatusSummary/ListAlarmsStatus)  [GetAlarmHistory](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmHistoryCollection/GetAlarmHistory) and [RetrieveDimensionStates](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmDimensionStatesCollection/RetrieveDimensionStates).
     * 
     */
    private String alarmSummary;
    /**
     * @return A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm.
     * 
     */
    private String id;
    /**
     * @return Identifier of the alarm&#39;s base values for alarm evaluation, for use when the alarm contains overrides.  Default value is `BASE`. For information about alarm overrides, see [AlarmOverride](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/AlarmOverride).
     * 
     */
    private String ruleName;
    /**
     * @return The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
     * 
     */
    private String severity;
    /**
     * @return The status of the metric stream to use for alarm filtering. For example, set `StatusQueryParam` to &#34;FIRING&#34; to filter results to metric streams of the alarm with that status. Default behaviour is to return alarms irrespective of metric streams&#39; status.  Example: `FIRING`
     * 
     */
    private String status;
    /**
     * @return The configuration details for suppressing an alarm.
     * 
     */
    private List<GetAlarmStatusesAlarmStatusSuppression> suppressions;
    /**
     * @return Timestamp for the transition of the alarm state. For example, the time when the alarm transitioned from OK to Firing. Note: A three-minute lag for this value accounts for any late-arriving metrics.  Example: `2023-02-01T01:02:29.600Z`
     * 
     */
    private String timestampTriggered;

    private GetAlarmStatusesAlarmStatus() {}
    /**
     * @return Customizable alarm summary (`alarmSummary` [alarm message parameter](https://docs.cloud.oracle.com/iaas/Content/Monitoring/alarm-message-format.htm)). Optionally include [dynamic variables](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/update-alarm-dynamic-variables.htm). The alarm summary appears within the body of the alarm message and in responses to  [ListAlarmStatus](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmStatusSummary/ListAlarmsStatus)  [GetAlarmHistory](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmHistoryCollection/GetAlarmHistory) and [RetrieveDimensionStates](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmDimensionStatesCollection/RetrieveDimensionStates).
     * 
     */
    public String alarmSummary() {
        return this.alarmSummary;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Identifier of the alarm&#39;s base values for alarm evaluation, for use when the alarm contains overrides.  Default value is `BASE`. For information about alarm overrides, see [AlarmOverride](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/AlarmOverride).
     * 
     */
    public String ruleName() {
        return this.ruleName;
    }
    /**
     * @return The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
     * 
     */
    public String severity() {
        return this.severity;
    }
    /**
     * @return The status of the metric stream to use for alarm filtering. For example, set `StatusQueryParam` to &#34;FIRING&#34; to filter results to metric streams of the alarm with that status. Default behaviour is to return alarms irrespective of metric streams&#39; status.  Example: `FIRING`
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The configuration details for suppressing an alarm.
     * 
     */
    public List<GetAlarmStatusesAlarmStatusSuppression> suppressions() {
        return this.suppressions;
    }
    /**
     * @return Timestamp for the transition of the alarm state. For example, the time when the alarm transitioned from OK to Firing. Note: A three-minute lag for this value accounts for any late-arriving metrics.  Example: `2023-02-01T01:02:29.600Z`
     * 
     */
    public String timestampTriggered() {
        return this.timestampTriggered;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlarmStatusesAlarmStatus defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String alarmSummary;
        private String displayName;
        private String id;
        private String ruleName;
        private String severity;
        private String status;
        private List<GetAlarmStatusesAlarmStatusSuppression> suppressions;
        private String timestampTriggered;
        public Builder() {}
        public Builder(GetAlarmStatusesAlarmStatus defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alarmSummary = defaults.alarmSummary;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.ruleName = defaults.ruleName;
    	      this.severity = defaults.severity;
    	      this.status = defaults.status;
    	      this.suppressions = defaults.suppressions;
    	      this.timestampTriggered = defaults.timestampTriggered;
        }

        @CustomType.Setter
        public Builder alarmSummary(String alarmSummary) {
            if (alarmSummary == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "alarmSummary");
            }
            this.alarmSummary = alarmSummary;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ruleName(String ruleName) {
            if (ruleName == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "ruleName");
            }
            this.ruleName = ruleName;
            return this;
        }
        @CustomType.Setter
        public Builder severity(String severity) {
            if (severity == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "severity");
            }
            this.severity = severity;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder suppressions(List<GetAlarmStatusesAlarmStatusSuppression> suppressions) {
            if (suppressions == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "suppressions");
            }
            this.suppressions = suppressions;
            return this;
        }
        public Builder suppressions(GetAlarmStatusesAlarmStatusSuppression... suppressions) {
            return suppressions(List.of(suppressions));
        }
        @CustomType.Setter
        public Builder timestampTriggered(String timestampTriggered) {
            if (timestampTriggered == null) {
              throw new MissingRequiredPropertyException("GetAlarmStatusesAlarmStatus", "timestampTriggered");
            }
            this.timestampTriggered = timestampTriggered;
            return this;
        }
        public GetAlarmStatusesAlarmStatus build() {
            final var _resultValue = new GetAlarmStatusesAlarmStatus();
            _resultValue.alarmSummary = alarmSummary;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.ruleName = ruleName;
            _resultValue.severity = severity;
            _resultValue.status = status;
            _resultValue.suppressions = suppressions;
            _resultValue.timestampTriggered = timestampTriggered;
            return _resultValue;
        }
    }
}
