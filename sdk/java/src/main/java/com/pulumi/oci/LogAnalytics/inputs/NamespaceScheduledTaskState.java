// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LogAnalytics.inputs.NamespaceScheduledTaskActionArgs;
import com.pulumi.oci.LogAnalytics.inputs.NamespaceScheduledTaskSchedulesArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NamespaceScheduledTaskState extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceScheduledTaskState Empty = new NamespaceScheduledTaskState();

    /**
     * Action for scheduled task.
     * 
     */
    @Import(name="action")
    private @Nullable Output<NamespaceScheduledTaskActionArgs> action;

    /**
     * @return Action for scheduled task.
     * 
     */
    public Optional<Output<NamespaceScheduledTaskActionArgs>> action() {
        return Optional.ofNullable(this.action);
    }

    /**
     * (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
     * (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
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
     * (Updatable) Discriminator.
     * 
     */
    @Import(name="kind")
    private @Nullable Output<String> kind;

    /**
     * @return (Updatable) Discriminator.
     * 
     */
    public Optional<Output<String>> kind() {
        return Optional.ofNullable(this.kind);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * Number of execution occurrences.
     * 
     */
    @Import(name="numOccurrences")
    private @Nullable Output<String> numOccurrences;

    /**
     * @return Number of execution occurrences.
     * 
     */
    public Optional<Output<String>> numOccurrences() {
        return Optional.ofNullable(this.numOccurrences);
    }

    /**
     * The ManagementSavedSearch id [OCID] to be accelerated.
     * 
     */
    @Import(name="savedSearchId")
    private @Nullable Output<String> savedSearchId;

    /**
     * @return The ManagementSavedSearch id [OCID] to be accelerated.
     * 
     */
    public Optional<Output<String>> savedSearchId() {
        return Optional.ofNullable(this.savedSearchId);
    }

    @Import(name="scheduledTaskId")
    private @Nullable Output<String> scheduledTaskId;

    public Optional<Output<String>> scheduledTaskId() {
        return Optional.ofNullable(this.scheduledTaskId);
    }

    /**
     * (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
     * 
     */
    @Import(name="schedules")
    private @Nullable Output<NamespaceScheduledTaskSchedulesArgs> schedules;

    /**
     * @return (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
     * 
     */
    public Optional<Output<NamespaceScheduledTaskSchedulesArgs>> schedules() {
        return Optional.ofNullable(this.schedules);
    }

    /**
     * The current state of the scheduled task.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the scheduled task.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
     * 
     */
    @Import(name="taskStatus")
    private @Nullable Output<String> taskStatus;

    /**
     * @return Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
     * 
     */
    public Optional<Output<String>> taskStatus() {
        return Optional.ofNullable(this.taskStatus);
    }

    /**
     * Task type.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="taskType")
    private @Nullable Output<String> taskType;

    /**
     * @return Task type.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> taskType() {
        return Optional.ofNullable(this.taskType);
    }

    /**
     * The date and time the scheduled task was created, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the scheduled task was created, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the scheduled task was last updated, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the scheduled task was last updated, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
     * 
     */
    @Import(name="workRequestId")
    private @Nullable Output<String> workRequestId;

    /**
     * @return most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
     * 
     */
    public Optional<Output<String>> workRequestId() {
        return Optional.ofNullable(this.workRequestId);
    }

    private NamespaceScheduledTaskState() {}

    private NamespaceScheduledTaskState(NamespaceScheduledTaskState $) {
        this.action = $.action;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.kind = $.kind;
        this.namespace = $.namespace;
        this.numOccurrences = $.numOccurrences;
        this.savedSearchId = $.savedSearchId;
        this.scheduledTaskId = $.scheduledTaskId;
        this.schedules = $.schedules;
        this.state = $.state;
        this.taskStatus = $.taskStatus;
        this.taskType = $.taskType;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.workRequestId = $.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceScheduledTaskState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceScheduledTaskState $;

        public Builder() {
            $ = new NamespaceScheduledTaskState();
        }

        public Builder(NamespaceScheduledTaskState defaults) {
            $ = new NamespaceScheduledTaskState(Objects.requireNonNull(defaults));
        }

        /**
         * @param action Action for scheduled task.
         * 
         * @return builder
         * 
         */
        public Builder action(@Nullable Output<NamespaceScheduledTaskActionArgs> action) {
            $.action = action;
            return this;
        }

        /**
         * @param action Action for scheduled task.
         * 
         * @return builder
         * 
         */
        public Builder action(NamespaceScheduledTaskActionArgs action) {
            return action(Output.of(action));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
         * @param displayName (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
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
         * @param kind (Updatable) Discriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(@Nullable Output<String> kind) {
            $.kind = kind;
            return this;
        }

        /**
         * @param kind (Updatable) Discriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(String kind) {
            return kind(Output.of(kind));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param numOccurrences Number of execution occurrences.
         * 
         * @return builder
         * 
         */
        public Builder numOccurrences(@Nullable Output<String> numOccurrences) {
            $.numOccurrences = numOccurrences;
            return this;
        }

        /**
         * @param numOccurrences Number of execution occurrences.
         * 
         * @return builder
         * 
         */
        public Builder numOccurrences(String numOccurrences) {
            return numOccurrences(Output.of(numOccurrences));
        }

        /**
         * @param savedSearchId The ManagementSavedSearch id [OCID] to be accelerated.
         * 
         * @return builder
         * 
         */
        public Builder savedSearchId(@Nullable Output<String> savedSearchId) {
            $.savedSearchId = savedSearchId;
            return this;
        }

        /**
         * @param savedSearchId The ManagementSavedSearch id [OCID] to be accelerated.
         * 
         * @return builder
         * 
         */
        public Builder savedSearchId(String savedSearchId) {
            return savedSearchId(Output.of(savedSearchId));
        }

        public Builder scheduledTaskId(@Nullable Output<String> scheduledTaskId) {
            $.scheduledTaskId = scheduledTaskId;
            return this;
        }

        public Builder scheduledTaskId(String scheduledTaskId) {
            return scheduledTaskId(Output.of(scheduledTaskId));
        }

        /**
         * @param schedules (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
         * 
         * @return builder
         * 
         */
        public Builder schedules(@Nullable Output<NamespaceScheduledTaskSchedulesArgs> schedules) {
            $.schedules = schedules;
            return this;
        }

        /**
         * @param schedules (Updatable) Schedules, typically a single schedule. Note there may only be a single schedule for SAVED_SEARCH and PURGE scheduled tasks.
         * 
         * @return builder
         * 
         */
        public Builder schedules(NamespaceScheduledTaskSchedulesArgs schedules) {
            return schedules(Output.of(schedules));
        }

        /**
         * @param state The current state of the scheduled task.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the scheduled task.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param taskStatus Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
         * 
         * @return builder
         * 
         */
        public Builder taskStatus(@Nullable Output<String> taskStatus) {
            $.taskStatus = taskStatus;
            return this;
        }

        /**
         * @param taskStatus Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
         * 
         * @return builder
         * 
         */
        public Builder taskStatus(String taskStatus) {
            return taskStatus(Output.of(taskStatus));
        }

        /**
         * @param taskType Task type.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder taskType(@Nullable Output<String> taskType) {
            $.taskType = taskType;
            return this;
        }

        /**
         * @param taskType Task type.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder taskType(String taskType) {
            return taskType(Output.of(taskType));
        }

        /**
         * @param timeCreated The date and time the scheduled task was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the scheduled task was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the scheduled task was last updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the scheduled task was last updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param workRequestId most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
         * 
         * @return builder
         * 
         */
        public Builder workRequestId(@Nullable Output<String> workRequestId) {
            $.workRequestId = workRequestId;
            return this;
        }

        /**
         * @param workRequestId most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
         * 
         * @return builder
         * 
         */
        public Builder workRequestId(String workRequestId) {
            return workRequestId(Output.of(workRequestId));
        }

        public NamespaceScheduledTaskState build() {
            return $;
        }
    }

}
