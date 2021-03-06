// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Monitoring.outputs.GetAlarmSuppression;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAlarmResult {
    private final String alarmId;
    /**
     * @return The human-readable content of the notification delivered. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices.  Example: `High CPU usage alert. Follow runbook instructions for resolution.`
     * 
     */
    private final String body;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
     * 
     */
    private final String compartmentId;
    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
     * 
     */
    private final List<String> destinations;
    /**
     * @return A user-friendly name for the alarm. It does not have to be unique, and it&#39;s changeable.
     * 
     */
    private final String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm.
     * 
     */
    private final String id;
    /**
     * @return Whether the alarm is enabled.  Example: `true`
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return The format to use for notification messages sent from this alarm. The formats are:
     * 
     */
    private final String messageFormat;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric being evaluated by the alarm.
     * 
     */
    private final String metricCompartmentId;
    /**
     * @return When true, the alarm evaluates metrics from all compartments and subcompartments. The parameter can only be set to true when metricCompartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, the alarm evaluates metrics from only the compartment specified in metricCompartmentId. Default is false.  Example: `true`
     * 
     */
    private final Boolean metricCompartmentIdInSubtree;
    /**
     * @return The source service or application emitting the metric that is evaluated by the alarm.  Example: `oci_computeagent`
     * 
     */
    private final String namespace;
    /**
     * @return The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;. For example, a value of 5 minutes means that the alarm must persist in breaching the condition for five minutes before the alarm updates its state to &#34;FIRING&#34;.
     * 
     */
    private final String pendingDuration;
    /**
     * @return The Monitoring Query Language (MQL) expression to evaluate for the alarm. The Alarms feature of the Monitoring service interprets results for each returned time series as Boolean values, where zero represents false and a non-zero value represents true. A true value means that the trigger rule condition has been met. The query must specify a metric, statistic, interval, and trigger rule (threshold or absence). Supported values for interval depend on the specified time range. More interval values are supported for smaller time ranges. You can optionally specify dimensions and grouping functions. Supported grouping functions: `grouping()`, `groupBy()`. For details about Monitoring Query Language (MQL), see [Monitoring Query Language (MQL) Reference](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Reference/mql.htm). For available dimensions, review the metric definition for the supported service. See [Supported Services](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#SupportedServices).
     * 
     */
    private final String query;
    /**
     * @return The frequency at which notifications are re-submitted, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, `PT4H` indicates four hours. Minimum: PT1M. Maximum: P30D.
     * 
     */
    private final String repeatNotificationDuration;
    /**
     * @return The time between calculated aggregation windows for the alarm. Supported value: `1m`
     * 
     */
    private final String resolution;
    /**
     * @return Resource group to match for metric data retrieved by the alarm. A resource group is a custom string that you can match when retrieving custom metrics. Only one resource group can be applied per metric. A valid resourceGroup value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($).  Example: `frontend-fleet`
     * 
     */
    private final String resourceGroup;
    /**
     * @return The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
     * 
     */
    private final String severity;
    /**
     * @return The current lifecycle state of the alarm.  Example: `DELETED`
     * 
     */
    private final String state;
    /**
     * @return The configuration details for suppressing an alarm.
     * 
     */
    private final List<GetAlarmSuppression> suppressions;
    /**
     * @return The date and time the alarm was created. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the alarm was last updated. Format defined by RFC3339.  Example: `2019-02-03T01:02:29.600Z`
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetAlarmResult(
        @CustomType.Parameter("alarmId") String alarmId,
        @CustomType.Parameter("body") String body,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("destinations") List<String> destinations,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("messageFormat") String messageFormat,
        @CustomType.Parameter("metricCompartmentId") String metricCompartmentId,
        @CustomType.Parameter("metricCompartmentIdInSubtree") Boolean metricCompartmentIdInSubtree,
        @CustomType.Parameter("namespace") String namespace,
        @CustomType.Parameter("pendingDuration") String pendingDuration,
        @CustomType.Parameter("query") String query,
        @CustomType.Parameter("repeatNotificationDuration") String repeatNotificationDuration,
        @CustomType.Parameter("resolution") String resolution,
        @CustomType.Parameter("resourceGroup") String resourceGroup,
        @CustomType.Parameter("severity") String severity,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("suppressions") List<GetAlarmSuppression> suppressions,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.alarmId = alarmId;
        this.body = body;
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.destinations = destinations;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isEnabled = isEnabled;
        this.messageFormat = messageFormat;
        this.metricCompartmentId = metricCompartmentId;
        this.metricCompartmentIdInSubtree = metricCompartmentIdInSubtree;
        this.namespace = namespace;
        this.pendingDuration = pendingDuration;
        this.query = query;
        this.repeatNotificationDuration = repeatNotificationDuration;
        this.resolution = resolution;
        this.resourceGroup = resourceGroup;
        this.severity = severity;
        this.state = state;
        this.suppressions = suppressions;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    public String alarmId() {
        return this.alarmId;
    }
    /**
     * @return The human-readable content of the notification delivered. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices.  Example: `High CPU usage alert. Follow runbook instructions for resolution.`
     * 
     */
    public String body() {
        return this.body;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
     * 
     */
    public List<String> destinations() {
        return this.destinations;
    }
    /**
     * @return A user-friendly name for the alarm. It does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether the alarm is enabled.  Example: `true`
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The format to use for notification messages sent from this alarm. The formats are:
     * 
     */
    public String messageFormat() {
        return this.messageFormat;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric being evaluated by the alarm.
     * 
     */
    public String metricCompartmentId() {
        return this.metricCompartmentId;
    }
    /**
     * @return When true, the alarm evaluates metrics from all compartments and subcompartments. The parameter can only be set to true when metricCompartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, the alarm evaluates metrics from only the compartment specified in metricCompartmentId. Default is false.  Example: `true`
     * 
     */
    public Boolean metricCompartmentIdInSubtree() {
        return this.metricCompartmentIdInSubtree;
    }
    /**
     * @return The source service or application emitting the metric that is evaluated by the alarm.  Example: `oci_computeagent`
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;. For example, a value of 5 minutes means that the alarm must persist in breaching the condition for five minutes before the alarm updates its state to &#34;FIRING&#34;.
     * 
     */
    public String pendingDuration() {
        return this.pendingDuration;
    }
    /**
     * @return The Monitoring Query Language (MQL) expression to evaluate for the alarm. The Alarms feature of the Monitoring service interprets results for each returned time series as Boolean values, where zero represents false and a non-zero value represents true. A true value means that the trigger rule condition has been met. The query must specify a metric, statistic, interval, and trigger rule (threshold or absence). Supported values for interval depend on the specified time range. More interval values are supported for smaller time ranges. You can optionally specify dimensions and grouping functions. Supported grouping functions: `grouping()`, `groupBy()`. For details about Monitoring Query Language (MQL), see [Monitoring Query Language (MQL) Reference](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Reference/mql.htm). For available dimensions, review the metric definition for the supported service. See [Supported Services](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#SupportedServices).
     * 
     */
    public String query() {
        return this.query;
    }
    /**
     * @return The frequency at which notifications are re-submitted, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, `PT4H` indicates four hours. Minimum: PT1M. Maximum: P30D.
     * 
     */
    public String repeatNotificationDuration() {
        return this.repeatNotificationDuration;
    }
    /**
     * @return The time between calculated aggregation windows for the alarm. Supported value: `1m`
     * 
     */
    public String resolution() {
        return this.resolution;
    }
    /**
     * @return Resource group to match for metric data retrieved by the alarm. A resource group is a custom string that you can match when retrieving custom metrics. Only one resource group can be applied per metric. A valid resourceGroup value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($).  Example: `frontend-fleet`
     * 
     */
    public String resourceGroup() {
        return this.resourceGroup;
    }
    /**
     * @return The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
     * 
     */
    public String severity() {
        return this.severity;
    }
    /**
     * @return The current lifecycle state of the alarm.  Example: `DELETED`
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The configuration details for suppressing an alarm.
     * 
     */
    public List<GetAlarmSuppression> suppressions() {
        return this.suppressions;
    }
    /**
     * @return The date and time the alarm was created. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the alarm was last updated. Format defined by RFC3339.  Example: `2019-02-03T01:02:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlarmResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String alarmId;
        private String body;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private List<String> destinations;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String messageFormat;
        private String metricCompartmentId;
        private Boolean metricCompartmentIdInSubtree;
        private String namespace;
        private String pendingDuration;
        private String query;
        private String repeatNotificationDuration;
        private String resolution;
        private String resourceGroup;
        private String severity;
        private String state;
        private List<GetAlarmSuppression> suppressions;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAlarmResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alarmId = defaults.alarmId;
    	      this.body = defaults.body;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.destinations = defaults.destinations;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.messageFormat = defaults.messageFormat;
    	      this.metricCompartmentId = defaults.metricCompartmentId;
    	      this.metricCompartmentIdInSubtree = defaults.metricCompartmentIdInSubtree;
    	      this.namespace = defaults.namespace;
    	      this.pendingDuration = defaults.pendingDuration;
    	      this.query = defaults.query;
    	      this.repeatNotificationDuration = defaults.repeatNotificationDuration;
    	      this.resolution = defaults.resolution;
    	      this.resourceGroup = defaults.resourceGroup;
    	      this.severity = defaults.severity;
    	      this.state = defaults.state;
    	      this.suppressions = defaults.suppressions;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder alarmId(String alarmId) {
            this.alarmId = Objects.requireNonNull(alarmId);
            return this;
        }
        public Builder body(String body) {
            this.body = Objects.requireNonNull(body);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder destinations(List<String> destinations) {
            this.destinations = Objects.requireNonNull(destinations);
            return this;
        }
        public Builder destinations(String... destinations) {
            return destinations(List.of(destinations));
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder messageFormat(String messageFormat) {
            this.messageFormat = Objects.requireNonNull(messageFormat);
            return this;
        }
        public Builder metricCompartmentId(String metricCompartmentId) {
            this.metricCompartmentId = Objects.requireNonNull(metricCompartmentId);
            return this;
        }
        public Builder metricCompartmentIdInSubtree(Boolean metricCompartmentIdInSubtree) {
            this.metricCompartmentIdInSubtree = Objects.requireNonNull(metricCompartmentIdInSubtree);
            return this;
        }
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        public Builder pendingDuration(String pendingDuration) {
            this.pendingDuration = Objects.requireNonNull(pendingDuration);
            return this;
        }
        public Builder query(String query) {
            this.query = Objects.requireNonNull(query);
            return this;
        }
        public Builder repeatNotificationDuration(String repeatNotificationDuration) {
            this.repeatNotificationDuration = Objects.requireNonNull(repeatNotificationDuration);
            return this;
        }
        public Builder resolution(String resolution) {
            this.resolution = Objects.requireNonNull(resolution);
            return this;
        }
        public Builder resourceGroup(String resourceGroup) {
            this.resourceGroup = Objects.requireNonNull(resourceGroup);
            return this;
        }
        public Builder severity(String severity) {
            this.severity = Objects.requireNonNull(severity);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder suppressions(List<GetAlarmSuppression> suppressions) {
            this.suppressions = Objects.requireNonNull(suppressions);
            return this;
        }
        public Builder suppressions(GetAlarmSuppression... suppressions) {
            return suppressions(List.of(suppressions));
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetAlarmResult build() {
            return new GetAlarmResult(alarmId, body, compartmentId, definedTags, destinations, displayName, freeformTags, id, isEnabled, messageFormat, metricCompartmentId, metricCompartmentIdInSubtree, namespace, pendingDuration, query, repeatNotificationDuration, resolution, resourceGroup, severity, state, suppressions, timeCreated, timeUpdated);
        }
    }
}
