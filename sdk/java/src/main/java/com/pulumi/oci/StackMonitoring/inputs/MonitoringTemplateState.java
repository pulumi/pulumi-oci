// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.MonitoringTemplateMemberArgs;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoringTemplateState extends com.pulumi.resources.ResourceArgs {

    public static final MonitoringTemplateState Empty = new MonitoringTemplateState();

    /**
     * The OCID of the compartment containing the monitoringTemplate.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the monitoringTemplate.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
     * 
     */
    @Import(name="destinations")
    private @Nullable Output<List<String>> destinations;

    /**
     * @return (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
     * 
     */
    public Optional<Output<List<String>>> destinations() {
        return Optional.ofNullable(this.destinations);
    }

    /**
     * (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
     * 
     */
    @Import(name="isAlarmsEnabled")
    private @Nullable Output<Boolean> isAlarmsEnabled;

    /**
     * @return (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
     * 
     */
    public Optional<Output<Boolean>> isAlarmsEnabled() {
        return Optional.ofNullable(this.isAlarmsEnabled);
    }

    /**
     * (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
     * 
     */
    @Import(name="isSplitNotificationEnabled")
    private @Nullable Output<Boolean> isSplitNotificationEnabled;

    /**
     * @return (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
     * 
     */
    public Optional<Output<Boolean>> isSplitNotificationEnabled() {
        return Optional.ofNullable(this.isSplitNotificationEnabled);
    }

    /**
     * (Updatable) List of members of this monitoring template
     * 
     */
    @Import(name="members")
    private @Nullable Output<List<MonitoringTemplateMemberArgs>> members;

    /**
     * @return (Updatable) List of members of this monitoring template
     * 
     */
    public Optional<Output<List<MonitoringTemplateMemberArgs>>> members() {
        return Optional.ofNullable(this.members);
    }

    /**
     * (Updatable) The format to use for alarm notifications.
     * 
     */
    @Import(name="messageFormat")
    private @Nullable Output<String> messageFormat;

    /**
     * @return (Updatable) The format to use for alarm notifications.
     * 
     */
    public Optional<Output<String>> messageFormat() {
        return Optional.ofNullable(this.messageFormat);
    }

    /**
     * (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="repeatNotificationDuration")
    private @Nullable Output<String> repeatNotificationDuration;

    /**
     * @return (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> repeatNotificationDuration() {
        return Optional.ofNullable(this.repeatNotificationDuration);
    }

    /**
     * The current lifecycle state of the monitoring template.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the monitoring template.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The current status of the monitoring template i.e. whether it is Applied or NotApplied.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The current status of the monitoring template i.e. whether it is Applied or NotApplied.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Import(name="tenantId")
    private @Nullable Output<String> tenantId;

    /**
     * @return Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Optional<Output<String>> tenantId() {
        return Optional.ofNullable(this.tenantId);
    }

    /**
     * The date and time the monitoringTemplate was created. Format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the monitoringTemplate was created. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * Total Alarm Conditions
     * 
     */
    @Import(name="totalAlarmConditions")
    private @Nullable Output<Double> totalAlarmConditions;

    /**
     * @return Total Alarm Conditions
     * 
     */
    public Optional<Output<Double>> totalAlarmConditions() {
        return Optional.ofNullable(this.totalAlarmConditions);
    }

    /**
     * Total Applied Alarm Conditions
     * 
     */
    @Import(name="totalAppliedAlarmConditions")
    private @Nullable Output<Double> totalAppliedAlarmConditions;

    /**
     * @return Total Applied Alarm Conditions
     * 
     */
    public Optional<Output<Double>> totalAppliedAlarmConditions() {
        return Optional.ofNullable(this.totalAppliedAlarmConditions);
    }

    private MonitoringTemplateState() {}

    private MonitoringTemplateState(MonitoringTemplateState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.destinations = $.destinations;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isAlarmsEnabled = $.isAlarmsEnabled;
        this.isSplitNotificationEnabled = $.isSplitNotificationEnabled;
        this.members = $.members;
        this.messageFormat = $.messageFormat;
        this.repeatNotificationDuration = $.repeatNotificationDuration;
        this.state = $.state;
        this.status = $.status;
        this.systemTags = $.systemTags;
        this.tenantId = $.tenantId;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.totalAlarmConditions = $.totalAlarmConditions;
        this.totalAppliedAlarmConditions = $.totalAppliedAlarmConditions;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoringTemplateState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoringTemplateState $;

        public Builder() {
            $ = new MonitoringTemplateState();
        }

        public Builder(MonitoringTemplateState defaults) {
            $ = new MonitoringTemplateState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment containing the monitoringTemplate.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment containing the monitoringTemplate.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param destinations (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
         * 
         * @return builder
         * 
         */
        public Builder destinations(@Nullable Output<List<String>> destinations) {
            $.destinations = destinations;
            return this;
        }

        /**
         * @param destinations (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
         * 
         * @return builder
         * 
         */
        public Builder destinations(List<String> destinations) {
            return destinations(Output.of(destinations));
        }

        /**
         * @param destinations (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
         * 
         * @return builder
         * 
         */
        public Builder destinations(String... destinations) {
            return destinations(List.of(destinations));
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isAlarmsEnabled (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
         * 
         * @return builder
         * 
         */
        public Builder isAlarmsEnabled(@Nullable Output<Boolean> isAlarmsEnabled) {
            $.isAlarmsEnabled = isAlarmsEnabled;
            return this;
        }

        /**
         * @param isAlarmsEnabled (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
         * 
         * @return builder
         * 
         */
        public Builder isAlarmsEnabled(Boolean isAlarmsEnabled) {
            return isAlarmsEnabled(Output.of(isAlarmsEnabled));
        }

        /**
         * @param isSplitNotificationEnabled (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
         * 
         * @return builder
         * 
         */
        public Builder isSplitNotificationEnabled(@Nullable Output<Boolean> isSplitNotificationEnabled) {
            $.isSplitNotificationEnabled = isSplitNotificationEnabled;
            return this;
        }

        /**
         * @param isSplitNotificationEnabled (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
         * 
         * @return builder
         * 
         */
        public Builder isSplitNotificationEnabled(Boolean isSplitNotificationEnabled) {
            return isSplitNotificationEnabled(Output.of(isSplitNotificationEnabled));
        }

        /**
         * @param members (Updatable) List of members of this monitoring template
         * 
         * @return builder
         * 
         */
        public Builder members(@Nullable Output<List<MonitoringTemplateMemberArgs>> members) {
            $.members = members;
            return this;
        }

        /**
         * @param members (Updatable) List of members of this monitoring template
         * 
         * @return builder
         * 
         */
        public Builder members(List<MonitoringTemplateMemberArgs> members) {
            return members(Output.of(members));
        }

        /**
         * @param members (Updatable) List of members of this monitoring template
         * 
         * @return builder
         * 
         */
        public Builder members(MonitoringTemplateMemberArgs... members) {
            return members(List.of(members));
        }

        /**
         * @param messageFormat (Updatable) The format to use for alarm notifications.
         * 
         * @return builder
         * 
         */
        public Builder messageFormat(@Nullable Output<String> messageFormat) {
            $.messageFormat = messageFormat;
            return this;
        }

        /**
         * @param messageFormat (Updatable) The format to use for alarm notifications.
         * 
         * @return builder
         * 
         */
        public Builder messageFormat(String messageFormat) {
            return messageFormat(Output.of(messageFormat));
        }

        /**
         * @param repeatNotificationDuration (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder repeatNotificationDuration(@Nullable Output<String> repeatNotificationDuration) {
            $.repeatNotificationDuration = repeatNotificationDuration;
            return this;
        }

        /**
         * @param repeatNotificationDuration (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder repeatNotificationDuration(String repeatNotificationDuration) {
            return repeatNotificationDuration(Output.of(repeatNotificationDuration));
        }

        /**
         * @param state The current lifecycle state of the monitoring template.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the monitoring template.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param status The current status of the monitoring template i.e. whether it is Applied or NotApplied.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The current status of the monitoring template i.e. whether it is Applied or NotApplied.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param tenantId Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder tenantId(@Nullable Output<String> tenantId) {
            $.tenantId = tenantId;
            return this;
        }

        /**
         * @param tenantId Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder tenantId(String tenantId) {
            return tenantId(Output.of(tenantId));
        }

        /**
         * @param timeCreated The date and time the monitoringTemplate was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the monitoringTemplate was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param totalAlarmConditions Total Alarm Conditions
         * 
         * @return builder
         * 
         */
        public Builder totalAlarmConditions(@Nullable Output<Double> totalAlarmConditions) {
            $.totalAlarmConditions = totalAlarmConditions;
            return this;
        }

        /**
         * @param totalAlarmConditions Total Alarm Conditions
         * 
         * @return builder
         * 
         */
        public Builder totalAlarmConditions(Double totalAlarmConditions) {
            return totalAlarmConditions(Output.of(totalAlarmConditions));
        }

        /**
         * @param totalAppliedAlarmConditions Total Applied Alarm Conditions
         * 
         * @return builder
         * 
         */
        public Builder totalAppliedAlarmConditions(@Nullable Output<Double> totalAppliedAlarmConditions) {
            $.totalAppliedAlarmConditions = totalAppliedAlarmConditions;
            return this;
        }

        /**
         * @param totalAppliedAlarmConditions Total Applied Alarm Conditions
         * 
         * @return builder
         * 
         */
        public Builder totalAppliedAlarmConditions(Double totalAppliedAlarmConditions) {
            return totalAppliedAlarmConditions(Output.of(totalAppliedAlarmConditions));
        }

        public MonitoringTemplateState build() {
            return $;
        }
    }

}
