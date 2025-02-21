// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.ScheduleActionArgs;
import com.pulumi.oci.DataScience.inputs.ScheduleLogDetailsArgs;
import com.pulumi.oci.DataScience.inputs.ScheduleTriggerArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ScheduleState extends com.pulumi.resources.ResourceArgs {

    public static final ScheduleState Empty = new ScheduleState();

    /**
     * (Updatable) The schedule action
     * 
     */
    @Import(name="action")
    private @Nullable Output<ScheduleActionArgs> action;

    /**
     * @return (Updatable) The schedule action
     * 
     */
    public Optional<Output<ScheduleActionArgs>> action() {
        return Optional.ofNullable(this.action);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the schedule.
     * 
     */
    @Import(name="createdBy")
    private @Nullable Output<String> createdBy;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the schedule.
     * 
     */
    public Optional<Output<String>> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A short description of the schedule.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A short description of the schedule.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Details about the action performed by the last schedule execution. Example: `Invoked ML Application trigger.`
     * 
     */
    @Import(name="lastScheduleRunDetails")
    private @Nullable Output<String> lastScheduleRunDetails;

    /**
     * @return Details about the action performed by the last schedule execution. Example: `Invoked ML Application trigger.`
     * 
     */
    public Optional<Output<String>> lastScheduleRunDetails() {
        return Optional.ofNullable(this.lastScheduleRunDetails);
    }

    /**
     * A message describing the current state in more detail.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) Custom logging details for schedule execution.
     * 
     */
    @Import(name="logDetails")
    private @Nullable Output<ScheduleLogDetailsArgs> logDetails;

    /**
     * @return (Updatable) Custom logging details for schedule execution.
     * 
     */
    public Optional<Output<ScheduleLogDetailsArgs>> logDetails() {
        return Optional.ofNullable(this.logDetails);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
     * 
     */
    @Import(name="projectId")
    private @Nullable Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
     * 
     */
    public Optional<Output<String>> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * The current state of the schedule.           Example: `ACTIVE`
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the schedule.           Example: `ACTIVE`
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
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
     * The date and time the schedule was created. Format is defined by RFC3339.           Example: `2022-08-05T01:02:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the schedule was created. Format is defined by RFC3339.           Example: `2022-08-05T01:02:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The last schedule execution time. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
     * 
     */
    @Import(name="timeLastScheduleRun")
    private @Nullable Output<String> timeLastScheduleRun;

    /**
     * @return The last schedule execution time. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
     * 
     */
    public Optional<Output<String>> timeLastScheduleRun() {
        return Optional.ofNullable(this.timeLastScheduleRun);
    }

    /**
     * The next scheduled execution time for the schedule. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
     * 
     */
    @Import(name="timeNextScheduledRun")
    private @Nullable Output<String> timeNextScheduledRun;

    /**
     * @return The next scheduled execution time for the schedule. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
     * 
     */
    public Optional<Output<String>> timeNextScheduledRun() {
        return Optional.ofNullable(this.timeNextScheduledRun);
    }

    /**
     * The date and time the schedule was updated. Format is defined by RFC3339.           Example: `2022-09-05T01:02:29.600Z`
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the schedule was updated. Format is defined by RFC3339.           Example: `2022-09-05T01:02:29.600Z`
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
     * 
     */
    @Import(name="trigger")
    private @Nullable Output<ScheduleTriggerArgs> trigger;

    /**
     * @return (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
     * 
     */
    public Optional<Output<ScheduleTriggerArgs>> trigger() {
        return Optional.ofNullable(this.trigger);
    }

    private ScheduleState() {}

    private ScheduleState(ScheduleState $) {
        this.action = $.action;
        this.compartmentId = $.compartmentId;
        this.createdBy = $.createdBy;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.lastScheduleRunDetails = $.lastScheduleRunDetails;
        this.lifecycleDetails = $.lifecycleDetails;
        this.logDetails = $.logDetails;
        this.projectId = $.projectId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeLastScheduleRun = $.timeLastScheduleRun;
        this.timeNextScheduledRun = $.timeNextScheduledRun;
        this.timeUpdated = $.timeUpdated;
        this.trigger = $.trigger;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ScheduleState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ScheduleState $;

        public Builder() {
            $ = new ScheduleState();
        }

        public Builder(ScheduleState defaults) {
            $ = new ScheduleState(Objects.requireNonNull(defaults));
        }

        /**
         * @param action (Updatable) The schedule action
         * 
         * @return builder
         * 
         */
        public Builder action(@Nullable Output<ScheduleActionArgs> action) {
            $.action = action;
            return this;
        }

        /**
         * @param action (Updatable) The schedule action
         * 
         * @return builder
         * 
         */
        public Builder action(ScheduleActionArgs action) {
            return action(Output.of(action));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the schedule.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param createdBy The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the schedule.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable Output<String> createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param createdBy The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the schedule.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(String createdBy) {
            return createdBy(Output.of(createdBy));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A short description of the schedule.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A short description of the schedule.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param lastScheduleRunDetails Details about the action performed by the last schedule execution. Example: `Invoked ML Application trigger.`
         * 
         * @return builder
         * 
         */
        public Builder lastScheduleRunDetails(@Nullable Output<String> lastScheduleRunDetails) {
            $.lastScheduleRunDetails = lastScheduleRunDetails;
            return this;
        }

        /**
         * @param lastScheduleRunDetails Details about the action performed by the last schedule execution. Example: `Invoked ML Application trigger.`
         * 
         * @return builder
         * 
         */
        public Builder lastScheduleRunDetails(String lastScheduleRunDetails) {
            return lastScheduleRunDetails(Output.of(lastScheduleRunDetails));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param logDetails (Updatable) Custom logging details for schedule execution.
         * 
         * @return builder
         * 
         */
        public Builder logDetails(@Nullable Output<ScheduleLogDetailsArgs> logDetails) {
            $.logDetails = logDetails;
            return this;
        }

        /**
         * @param logDetails (Updatable) Custom logging details for schedule execution.
         * 
         * @return builder
         * 
         */
        public Builder logDetails(ScheduleLogDetailsArgs logDetails) {
            return logDetails(Output.of(logDetails));
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the schedule with.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param state The current state of the schedule.           Example: `ACTIVE`
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the schedule.           Example: `ACTIVE`
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
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
         * @param timeCreated The date and time the schedule was created. Format is defined by RFC3339.           Example: `2022-08-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the schedule was created. Format is defined by RFC3339.           Example: `2022-08-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeLastScheduleRun The last schedule execution time. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeLastScheduleRun(@Nullable Output<String> timeLastScheduleRun) {
            $.timeLastScheduleRun = timeLastScheduleRun;
            return this;
        }

        /**
         * @param timeLastScheduleRun The last schedule execution time. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeLastScheduleRun(String timeLastScheduleRun) {
            return timeLastScheduleRun(Output.of(timeLastScheduleRun));
        }

        /**
         * @param timeNextScheduledRun The next scheduled execution time for the schedule. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeNextScheduledRun(@Nullable Output<String> timeNextScheduledRun) {
            $.timeNextScheduledRun = timeNextScheduledRun;
            return this;
        }

        /**
         * @param timeNextScheduledRun The next scheduled execution time for the schedule. Format is defined by RFC3339. Example: `2022-08-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeNextScheduledRun(String timeNextScheduledRun) {
            return timeNextScheduledRun(Output.of(timeNextScheduledRun));
        }

        /**
         * @param timeUpdated The date and time the schedule was updated. Format is defined by RFC3339.           Example: `2022-09-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the schedule was updated. Format is defined by RFC3339.           Example: `2022-09-05T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param trigger (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
         * 
         * @return builder
         * 
         */
        public Builder trigger(@Nullable Output<ScheduleTriggerArgs> trigger) {
            $.trigger = trigger;
            return this;
        }

        /**
         * @param trigger (Updatable) The trigger of the schedule can be UNIX cron or iCal expression or simple interval
         * 
         * @return builder
         * 
         */
        public Builder trigger(ScheduleTriggerArgs trigger) {
            return trigger(Output.of(trigger));
        }

        public ScheduleState build() {
            return $;
        }
    }

}
