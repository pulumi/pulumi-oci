// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTasksScheduledTaskCollectionItemAction;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTasksScheduledTaskCollectionItemSchedule;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTasksScheduledTaskCollectionItem {
    /**
     * @return Action for scheduled task.
     * 
     */
    private List<GetNamespaceScheduledTasksScheduledTaskCollectionItemAction> actions;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data plane resource.
     * 
     */
    private String id;
    private String kind;
    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    private String namespace;
    /**
     * @return Number of execution occurrences.
     * 
     */
    private String numOccurrences;
    /**
     * @return The ManagementSavedSearch id [OCID] utilized in the action.
     * 
     */
    private String savedSearchId;
    private String scheduledTaskId;
    /**
     * @return Schedules.
     * 
     */
    private List<GetNamespaceScheduledTasksScheduledTaskCollectionItemSchedule> schedules;
    /**
     * @return The current state of the scheduled task.
     * 
     */
    private String state;
    /**
     * @return Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
     * 
     */
    private String taskStatus;
    /**
     * @return Required parameter to specify schedule task type.
     * 
     */
    private String taskType;
    /**
     * @return The date and time the scheduled task was created, in the format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the scheduled task was last updated, in the format defined by RFC3339.
     * 
     */
    private String timeUpdated;
    /**
     * @return most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
     * 
     */
    private String workRequestId;

    private GetNamespaceScheduledTasksScheduledTaskCollectionItem() {}
    /**
     * @return Action for scheduled task.
     * 
     */
    public List<GetNamespaceScheduledTasksScheduledTaskCollectionItemAction> actions() {
        return this.actions;
    }
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data plane resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String kind() {
        return this.kind;
    }
    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return Number of execution occurrences.
     * 
     */
    public String numOccurrences() {
        return this.numOccurrences;
    }
    /**
     * @return The ManagementSavedSearch id [OCID] utilized in the action.
     * 
     */
    public String savedSearchId() {
        return this.savedSearchId;
    }
    public String scheduledTaskId() {
        return this.scheduledTaskId;
    }
    /**
     * @return Schedules.
     * 
     */
    public List<GetNamespaceScheduledTasksScheduledTaskCollectionItemSchedule> schedules() {
        return this.schedules;
    }
    /**
     * @return The current state of the scheduled task.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Status of the scheduled task. - PURGE_RESOURCE_NOT_FOUND
     * 
     */
    public String taskStatus() {
        return this.taskStatus;
    }
    /**
     * @return Required parameter to specify schedule task type.
     * 
     */
    public String taskType() {
        return this.taskType;
    }
    /**
     * @return The date and time the scheduled task was created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the scheduled task was last updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return most recent Work Request Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the asynchronous request.
     * 
     */
    public String workRequestId() {
        return this.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTasksScheduledTaskCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNamespaceScheduledTasksScheduledTaskCollectionItemAction> actions;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String kind;
        private String namespace;
        private String numOccurrences;
        private String savedSearchId;
        private String scheduledTaskId;
        private List<GetNamespaceScheduledTasksScheduledTaskCollectionItemSchedule> schedules;
        private String state;
        private String taskStatus;
        private String taskType;
        private String timeCreated;
        private String timeUpdated;
        private String workRequestId;
        public Builder() {}
        public Builder(GetNamespaceScheduledTasksScheduledTaskCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.kind = defaults.kind;
    	      this.namespace = defaults.namespace;
    	      this.numOccurrences = defaults.numOccurrences;
    	      this.savedSearchId = defaults.savedSearchId;
    	      this.scheduledTaskId = defaults.scheduledTaskId;
    	      this.schedules = defaults.schedules;
    	      this.state = defaults.state;
    	      this.taskStatus = defaults.taskStatus;
    	      this.taskType = defaults.taskType;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.workRequestId = defaults.workRequestId;
        }

        @CustomType.Setter
        public Builder actions(List<GetNamespaceScheduledTasksScheduledTaskCollectionItemAction> actions) {
            this.actions = Objects.requireNonNull(actions);
            return this;
        }
        public Builder actions(GetNamespaceScheduledTasksScheduledTaskCollectionItemAction... actions) {
            return actions(List.of(actions));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            this.kind = Objects.requireNonNull(kind);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder numOccurrences(String numOccurrences) {
            this.numOccurrences = Objects.requireNonNull(numOccurrences);
            return this;
        }
        @CustomType.Setter
        public Builder savedSearchId(String savedSearchId) {
            this.savedSearchId = Objects.requireNonNull(savedSearchId);
            return this;
        }
        @CustomType.Setter
        public Builder scheduledTaskId(String scheduledTaskId) {
            this.scheduledTaskId = Objects.requireNonNull(scheduledTaskId);
            return this;
        }
        @CustomType.Setter
        public Builder schedules(List<GetNamespaceScheduledTasksScheduledTaskCollectionItemSchedule> schedules) {
            this.schedules = Objects.requireNonNull(schedules);
            return this;
        }
        public Builder schedules(GetNamespaceScheduledTasksScheduledTaskCollectionItemSchedule... schedules) {
            return schedules(List.of(schedules));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder taskStatus(String taskStatus) {
            this.taskStatus = Objects.requireNonNull(taskStatus);
            return this;
        }
        @CustomType.Setter
        public Builder taskType(String taskType) {
            this.taskType = Objects.requireNonNull(taskType);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder workRequestId(String workRequestId) {
            this.workRequestId = Objects.requireNonNull(workRequestId);
            return this;
        }
        public GetNamespaceScheduledTasksScheduledTaskCollectionItem build() {
            final var o = new GetNamespaceScheduledTasksScheduledTaskCollectionItem();
            o.actions = actions;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.kind = kind;
            o.namespace = namespace;
            o.numOccurrences = numOccurrences;
            o.savedSearchId = savedSearchId;
            o.scheduledTaskId = scheduledTaskId;
            o.schedules = schedules;
            o.state = state;
            o.taskStatus = taskStatus;
            o.taskType = taskType;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.workRequestId = workRequestId;
            return o;
        }
    }
}