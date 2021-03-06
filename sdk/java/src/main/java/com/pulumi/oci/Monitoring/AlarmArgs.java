// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Monitoring.inputs.AlarmSuppressionArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AlarmArgs extends com.pulumi.resources.ResourceArgs {

    public static final AlarmArgs Empty = new AlarmArgs();

    /**
     * (Updatable) The human-readable content of the notification delivered. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.  Example: `High CPU usage alert. Follow runbook instructions for resolution.`
     * 
     */
    @Import(name="body")
    private @Nullable Output<String> body;

    /**
     * @return (Updatable) The human-readable content of the notification delivered. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.  Example: `High CPU usage alert. Follow runbook instructions for resolution.`
     * 
     */
    public Optional<Output<String>> body() {
        return Optional.ofNullable(this.body);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
     * 
     */
    @Import(name="destinations", required=true)
    private Output<List<String>> destinations;

    /**
     * @return (Updatable) A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
     * 
     */
    public Output<List<String>> destinations() {
        return this.destinations;
    }

    /**
     * (Updatable) A user-friendly name for the alarm. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the alarm. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Whether the alarm is enabled.  Example: `true`
     * 
     */
    @Import(name="isEnabled", required=true)
    private Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Whether the alarm is enabled.  Example: `true`
     * 
     */
    public Output<Boolean> isEnabled() {
        return this.isEnabled;
    }

    /**
     * (Updatable) The format to use for notification messages sent from this alarm. The formats are:
     * 
     */
    @Import(name="messageFormat")
    private @Nullable Output<String> messageFormat;

    /**
     * @return (Updatable) The format to use for notification messages sent from this alarm. The formats are:
     * 
     */
    public Optional<Output<String>> messageFormat() {
        return Optional.ofNullable(this.messageFormat);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric being evaluated by the alarm.
     * 
     */
    @Import(name="metricCompartmentId", required=true)
    private Output<String> metricCompartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric being evaluated by the alarm.
     * 
     */
    public Output<String> metricCompartmentId() {
        return this.metricCompartmentId;
    }

    /**
     * (Updatable) When true, the alarm evaluates metrics from all compartments and subcompartments. The parameter can only be set to true when metricCompartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, the alarm evaluates metrics from only the compartment specified in metricCompartmentId. Default is false.  Example: `true`
     * 
     */
    @Import(name="metricCompartmentIdInSubtree")
    private @Nullable Output<Boolean> metricCompartmentIdInSubtree;

    /**
     * @return (Updatable) When true, the alarm evaluates metrics from all compartments and subcompartments. The parameter can only be set to true when metricCompartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, the alarm evaluates metrics from only the compartment specified in metricCompartmentId. Default is false.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> metricCompartmentIdInSubtree() {
        return Optional.ofNullable(this.metricCompartmentIdInSubtree);
    }

    /**
     * (Updatable) The source service or application emitting the metric that is evaluated by the alarm.  Example: `oci_computeagent`
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return (Updatable) The source service or application emitting the metric that is evaluated by the alarm.  Example: `oci_computeagent`
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * (Updatable) The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;. For example, a value of 5 minutes means that the alarm must persist in breaching the condition for five minutes before the alarm updates its state to &#34;FIRING&#34;.
     * 
     */
    @Import(name="pendingDuration")
    private @Nullable Output<String> pendingDuration;

    /**
     * @return (Updatable) The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;. For example, a value of 5 minutes means that the alarm must persist in breaching the condition for five minutes before the alarm updates its state to &#34;FIRING&#34;.
     * 
     */
    public Optional<Output<String>> pendingDuration() {
        return Optional.ofNullable(this.pendingDuration);
    }

    /**
     * (Updatable) The Monitoring Query Language (MQL) expression to evaluate for the alarm. The Alarms feature of the Monitoring service interprets results for each returned time series as Boolean values, where zero represents false and a non-zero value represents true. A true value means that the trigger rule condition has been met. The query must specify a metric, statistic, interval, and trigger rule (threshold or absence). Supported values for interval depend on the specified time range. More interval values are supported for smaller time ranges. You can optionally specify dimensions and grouping functions. Supported grouping functions: `grouping()`, `groupBy()`. For details about Monitoring Query Language (MQL), see [Monitoring Query Language (MQL) Reference](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Reference/mql.htm). For available dimensions, review the metric definition for the supported service. See [Supported Services](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#SupportedServices).
     * 
     */
    @Import(name="query", required=true)
    private Output<String> query;

    /**
     * @return (Updatable) The Monitoring Query Language (MQL) expression to evaluate for the alarm. The Alarms feature of the Monitoring service interprets results for each returned time series as Boolean values, where zero represents false and a non-zero value represents true. A true value means that the trigger rule condition has been met. The query must specify a metric, statistic, interval, and trigger rule (threshold or absence). Supported values for interval depend on the specified time range. More interval values are supported for smaller time ranges. You can optionally specify dimensions and grouping functions. Supported grouping functions: `grouping()`, `groupBy()`. For details about Monitoring Query Language (MQL), see [Monitoring Query Language (MQL) Reference](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Reference/mql.htm). For available dimensions, review the metric definition for the supported service. See [Supported Services](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#SupportedServices).
     * 
     */
    public Output<String> query() {
        return this.query;
    }

    /**
     * (Updatable) The frequency at which notifications are re-submitted, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, `PT4H` indicates four hours. Minimum: PT1M. Maximum: P30D.
     * 
     */
    @Import(name="repeatNotificationDuration")
    private @Nullable Output<String> repeatNotificationDuration;

    /**
     * @return (Updatable) The frequency at which notifications are re-submitted, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, `PT4H` indicates four hours. Minimum: PT1M. Maximum: P30D.
     * 
     */
    public Optional<Output<String>> repeatNotificationDuration() {
        return Optional.ofNullable(this.repeatNotificationDuration);
    }

    /**
     * (Updatable) The time between calculated aggregation windows for the alarm. Supported value: `1m`
     * 
     */
    @Import(name="resolution")
    private @Nullable Output<String> resolution;

    /**
     * @return (Updatable) The time between calculated aggregation windows for the alarm. Supported value: `1m`
     * 
     */
    public Optional<Output<String>> resolution() {
        return Optional.ofNullable(this.resolution);
    }

    /**
     * (Updatable) Resource group that you want to match. A null value returns only metric data that has no resource groups. The alarm retrieves metric data associated with the specified resource group only. Only one resource group can be applied per metric. A valid resourceGroup value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($). Avoid entering confidential information.  Example: `frontend-fleet`
     * 
     */
    @Import(name="resourceGroup")
    private @Nullable Output<String> resourceGroup;

    /**
     * @return (Updatable) Resource group that you want to match. A null value returns only metric data that has no resource groups. The alarm retrieves metric data associated with the specified resource group only. Only one resource group can be applied per metric. A valid resourceGroup value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($). Avoid entering confidential information.  Example: `frontend-fleet`
     * 
     */
    public Optional<Output<String>> resourceGroup() {
        return Optional.ofNullable(this.resourceGroup);
    }

    /**
     * (Updatable) The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
     * 
     */
    @Import(name="severity", required=true)
    private Output<String> severity;

    /**
     * @return (Updatable) The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
     * 
     */
    public Output<String> severity() {
        return this.severity;
    }

    /**
     * (Updatable) The configuration details for suppressing an alarm.
     * 
     */
    @Import(name="suppression")
    private @Nullable Output<AlarmSuppressionArgs> suppression;

    /**
     * @return (Updatable) The configuration details for suppressing an alarm.
     * 
     */
    public Optional<Output<AlarmSuppressionArgs>> suppression() {
        return Optional.ofNullable(this.suppression);
    }

    private AlarmArgs() {}

    private AlarmArgs(AlarmArgs $) {
        this.body = $.body;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.destinations = $.destinations;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isEnabled = $.isEnabled;
        this.messageFormat = $.messageFormat;
        this.metricCompartmentId = $.metricCompartmentId;
        this.metricCompartmentIdInSubtree = $.metricCompartmentIdInSubtree;
        this.namespace = $.namespace;
        this.pendingDuration = $.pendingDuration;
        this.query = $.query;
        this.repeatNotificationDuration = $.repeatNotificationDuration;
        this.resolution = $.resolution;
        this.resourceGroup = $.resourceGroup;
        this.severity = $.severity;
        this.suppression = $.suppression;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AlarmArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AlarmArgs $;

        public Builder() {
            $ = new AlarmArgs();
        }

        public Builder(AlarmArgs defaults) {
            $ = new AlarmArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param body (Updatable) The human-readable content of the notification delivered. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.  Example: `High CPU usage alert. Follow runbook instructions for resolution.`
         * 
         * @return builder
         * 
         */
        public Builder body(@Nullable Output<String> body) {
            $.body = body;
            return this;
        }

        /**
         * @param body (Updatable) The human-readable content of the notification delivered. Oracle recommends providing guidance to operators for resolving the alarm condition. Consider adding links to standard runbook practices. Avoid entering confidential information.  Example: `High CPU usage alert. Follow runbook instructions for resolution.`
         * 
         * @return builder
         * 
         */
        public Builder body(String body) {
            return body(Output.of(body));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param destinations (Updatable) A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
         * 
         * @return builder
         * 
         */
        public Builder destinations(Output<List<String>> destinations) {
            $.destinations = destinations;
            return this;
        }

        /**
         * @param destinations (Updatable) A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
         * 
         * @return builder
         * 
         */
        public Builder destinations(List<String> destinations) {
            return destinations(Output.of(destinations));
        }

        /**
         * @param destinations (Updatable) A list of destinations to which the notifications for this alarm will be delivered. Each destination is represented by an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) related to the supported destination service. For example, a destination using the Notifications service is represented by a topic OCID. Supported destination services: Notifications Service. Limit: One destination per supported destination service.
         * 
         * @return builder
         * 
         */
        public Builder destinations(String... destinations) {
            return destinations(List.of(destinations));
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the alarm. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the alarm. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isEnabled (Updatable) Whether the alarm is enabled.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Whether the alarm is enabled.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param messageFormat (Updatable) The format to use for notification messages sent from this alarm. The formats are:
         * 
         * @return builder
         * 
         */
        public Builder messageFormat(@Nullable Output<String> messageFormat) {
            $.messageFormat = messageFormat;
            return this;
        }

        /**
         * @param messageFormat (Updatable) The format to use for notification messages sent from this alarm. The formats are:
         * 
         * @return builder
         * 
         */
        public Builder messageFormat(String messageFormat) {
            return messageFormat(Output.of(messageFormat));
        }

        /**
         * @param metricCompartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric being evaluated by the alarm.
         * 
         * @return builder
         * 
         */
        public Builder metricCompartmentId(Output<String> metricCompartmentId) {
            $.metricCompartmentId = metricCompartmentId;
            return this;
        }

        /**
         * @param metricCompartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric being evaluated by the alarm.
         * 
         * @return builder
         * 
         */
        public Builder metricCompartmentId(String metricCompartmentId) {
            return metricCompartmentId(Output.of(metricCompartmentId));
        }

        /**
         * @param metricCompartmentIdInSubtree (Updatable) When true, the alarm evaluates metrics from all compartments and subcompartments. The parameter can only be set to true when metricCompartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, the alarm evaluates metrics from only the compartment specified in metricCompartmentId. Default is false.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder metricCompartmentIdInSubtree(@Nullable Output<Boolean> metricCompartmentIdInSubtree) {
            $.metricCompartmentIdInSubtree = metricCompartmentIdInSubtree;
            return this;
        }

        /**
         * @param metricCompartmentIdInSubtree (Updatable) When true, the alarm evaluates metrics from all compartments and subcompartments. The parameter can only be set to true when metricCompartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, the alarm evaluates metrics from only the compartment specified in metricCompartmentId. Default is false.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder metricCompartmentIdInSubtree(Boolean metricCompartmentIdInSubtree) {
            return metricCompartmentIdInSubtree(Output.of(metricCompartmentIdInSubtree));
        }

        /**
         * @param namespace (Updatable) The source service or application emitting the metric that is evaluated by the alarm.  Example: `oci_computeagent`
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) The source service or application emitting the metric that is evaluated by the alarm.  Example: `oci_computeagent`
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param pendingDuration (Updatable) The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;. For example, a value of 5 minutes means that the alarm must persist in breaching the condition for five minutes before the alarm updates its state to &#34;FIRING&#34;.
         * 
         * @return builder
         * 
         */
        public Builder pendingDuration(@Nullable Output<String> pendingDuration) {
            $.pendingDuration = pendingDuration;
            return this;
        }

        /**
         * @param pendingDuration (Updatable) The period of time that the condition defined in the alarm must persist before the alarm state changes from &#34;OK&#34; to &#34;FIRING&#34;. For example, a value of 5 minutes means that the alarm must persist in breaching the condition for five minutes before the alarm updates its state to &#34;FIRING&#34;.
         * 
         * @return builder
         * 
         */
        public Builder pendingDuration(String pendingDuration) {
            return pendingDuration(Output.of(pendingDuration));
        }

        /**
         * @param query (Updatable) The Monitoring Query Language (MQL) expression to evaluate for the alarm. The Alarms feature of the Monitoring service interprets results for each returned time series as Boolean values, where zero represents false and a non-zero value represents true. A true value means that the trigger rule condition has been met. The query must specify a metric, statistic, interval, and trigger rule (threshold or absence). Supported values for interval depend on the specified time range. More interval values are supported for smaller time ranges. You can optionally specify dimensions and grouping functions. Supported grouping functions: `grouping()`, `groupBy()`. For details about Monitoring Query Language (MQL), see [Monitoring Query Language (MQL) Reference](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Reference/mql.htm). For available dimensions, review the metric definition for the supported service. See [Supported Services](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#SupportedServices).
         * 
         * @return builder
         * 
         */
        public Builder query(Output<String> query) {
            $.query = query;
            return this;
        }

        /**
         * @param query (Updatable) The Monitoring Query Language (MQL) expression to evaluate for the alarm. The Alarms feature of the Monitoring service interprets results for each returned time series as Boolean values, where zero represents false and a non-zero value represents true. A true value means that the trigger rule condition has been met. The query must specify a metric, statistic, interval, and trigger rule (threshold or absence). Supported values for interval depend on the specified time range. More interval values are supported for smaller time ranges. You can optionally specify dimensions and grouping functions. Supported grouping functions: `grouping()`, `groupBy()`. For details about Monitoring Query Language (MQL), see [Monitoring Query Language (MQL) Reference](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Reference/mql.htm). For available dimensions, review the metric definition for the supported service. See [Supported Services](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#SupportedServices).
         * 
         * @return builder
         * 
         */
        public Builder query(String query) {
            return query(Output.of(query));
        }

        /**
         * @param repeatNotificationDuration (Updatable) The frequency at which notifications are re-submitted, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, `PT4H` indicates four hours. Minimum: PT1M. Maximum: P30D.
         * 
         * @return builder
         * 
         */
        public Builder repeatNotificationDuration(@Nullable Output<String> repeatNotificationDuration) {
            $.repeatNotificationDuration = repeatNotificationDuration;
            return this;
        }

        /**
         * @param repeatNotificationDuration (Updatable) The frequency at which notifications are re-submitted, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, `PT4H` indicates four hours. Minimum: PT1M. Maximum: P30D.
         * 
         * @return builder
         * 
         */
        public Builder repeatNotificationDuration(String repeatNotificationDuration) {
            return repeatNotificationDuration(Output.of(repeatNotificationDuration));
        }

        /**
         * @param resolution (Updatable) The time between calculated aggregation windows for the alarm. Supported value: `1m`
         * 
         * @return builder
         * 
         */
        public Builder resolution(@Nullable Output<String> resolution) {
            $.resolution = resolution;
            return this;
        }

        /**
         * @param resolution (Updatable) The time between calculated aggregation windows for the alarm. Supported value: `1m`
         * 
         * @return builder
         * 
         */
        public Builder resolution(String resolution) {
            return resolution(Output.of(resolution));
        }

        /**
         * @param resourceGroup (Updatable) Resource group that you want to match. A null value returns only metric data that has no resource groups. The alarm retrieves metric data associated with the specified resource group only. Only one resource group can be applied per metric. A valid resourceGroup value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($). Avoid entering confidential information.  Example: `frontend-fleet`
         * 
         * @return builder
         * 
         */
        public Builder resourceGroup(@Nullable Output<String> resourceGroup) {
            $.resourceGroup = resourceGroup;
            return this;
        }

        /**
         * @param resourceGroup (Updatable) Resource group that you want to match. A null value returns only metric data that has no resource groups. The alarm retrieves metric data associated with the specified resource group only. Only one resource group can be applied per metric. A valid resourceGroup value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($). Avoid entering confidential information.  Example: `frontend-fleet`
         * 
         * @return builder
         * 
         */
        public Builder resourceGroup(String resourceGroup) {
            return resourceGroup(Output.of(resourceGroup));
        }

        /**
         * @param severity (Updatable) The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
         * 
         * @return builder
         * 
         */
        public Builder severity(Output<String> severity) {
            $.severity = severity;
            return this;
        }

        /**
         * @param severity (Updatable) The perceived type of response required when the alarm is in the &#34;FIRING&#34; state.  Example: `CRITICAL`
         * 
         * @return builder
         * 
         */
        public Builder severity(String severity) {
            return severity(Output.of(severity));
        }

        /**
         * @param suppression (Updatable) The configuration details for suppressing an alarm.
         * 
         * @return builder
         * 
         */
        public Builder suppression(@Nullable Output<AlarmSuppressionArgs> suppression) {
            $.suppression = suppression;
            return this;
        }

        /**
         * @param suppression (Updatable) The configuration details for suppressing an alarm.
         * 
         * @return builder
         * 
         */
        public Builder suppression(AlarmSuppressionArgs suppression) {
            return suppression(Output.of(suppression));
        }

        public AlarmArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.destinations = Objects.requireNonNull($.destinations, "expected parameter 'destinations' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.isEnabled = Objects.requireNonNull($.isEnabled, "expected parameter 'isEnabled' to be non-null");
            $.metricCompartmentId = Objects.requireNonNull($.metricCompartmentId, "expected parameter 'metricCompartmentId' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            $.query = Objects.requireNonNull($.query, "expected parameter 'query' to be non-null");
            $.severity = Objects.requireNonNull($.severity, "expected parameter 'severity' to be non-null");
            return $;
        }
    }

}
