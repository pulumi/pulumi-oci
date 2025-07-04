// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookVersionsRunbookVersionCollectionItemExecutionWorkflowDetail;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookVersionsRunbookVersionCollectionItemGroup;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookVersionsRunbookVersionCollectionItemRollbackWorkflowDetail;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookVersionsRunbookVersionCollectionItemTask;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetRunbookVersionsRunbookVersionCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Execution Workflow details.
     * 
     */
    private List<GetRunbookVersionsRunbookVersionCollectionItemExecutionWorkflowDetail> executionWorkflowDetails;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The groups of the runbook.
     * 
     */
    private List<GetRunbookVersionsRunbookVersionCollectionItemGroup> groups;
    /**
     * @return A filter to return runbook versions whose identifier matches the given identifier.
     * 
     */
    private String id;
    private Boolean isLatest;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    private String name;
    /**
     * @return Rollback Workflow details.
     * 
     */
    private List<GetRunbookVersionsRunbookVersionCollectionItemRollbackWorkflowDetail> rollbackWorkflowDetails;
    /**
     * @return A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
     * 
     */
    private String runbookId;
    /**
     * @return A filter to return only resources whose lifecycleState matches the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return A set of tasks to execute in the runbook.
     * 
     */
    private List<GetRunbookVersionsRunbookVersionCollectionItemTask> tasks;
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetRunbookVersionsRunbookVersionCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Execution Workflow details.
     * 
     */
    public List<GetRunbookVersionsRunbookVersionCollectionItemExecutionWorkflowDetail> executionWorkflowDetails() {
        return this.executionWorkflowDetails;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The groups of the runbook.
     * 
     */
    public List<GetRunbookVersionsRunbookVersionCollectionItemGroup> groups() {
        return this.groups;
    }
    /**
     * @return A filter to return runbook versions whose identifier matches the given identifier.
     * 
     */
    public String id() {
        return this.id;
    }
    public Boolean isLatest() {
        return this.isLatest;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Rollback Workflow details.
     * 
     */
    public List<GetRunbookVersionsRunbookVersionCollectionItemRollbackWorkflowDetail> rollbackWorkflowDetails() {
        return this.rollbackWorkflowDetails;
    }
    /**
     * @return A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
     * 
     */
    public String runbookId() {
        return this.runbookId;
    }
    /**
     * @return A filter to return only resources whose lifecycleState matches the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return A set of tasks to execute in the runbook.
     * 
     */
    public List<GetRunbookVersionsRunbookVersionCollectionItemTask> tasks() {
        return this.tasks;
    }
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookVersionsRunbookVersionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private List<GetRunbookVersionsRunbookVersionCollectionItemExecutionWorkflowDetail> executionWorkflowDetails;
        private Map<String,String> freeformTags;
        private List<GetRunbookVersionsRunbookVersionCollectionItemGroup> groups;
        private String id;
        private Boolean isLatest;
        private String lifecycleDetails;
        private String name;
        private List<GetRunbookVersionsRunbookVersionCollectionItemRollbackWorkflowDetail> rollbackWorkflowDetails;
        private String runbookId;
        private String state;
        private Map<String,String> systemTags;
        private List<GetRunbookVersionsRunbookVersionCollectionItemTask> tasks;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetRunbookVersionsRunbookVersionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.executionWorkflowDetails = defaults.executionWorkflowDetails;
    	      this.freeformTags = defaults.freeformTags;
    	      this.groups = defaults.groups;
    	      this.id = defaults.id;
    	      this.isLatest = defaults.isLatest;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.name = defaults.name;
    	      this.rollbackWorkflowDetails = defaults.rollbackWorkflowDetails;
    	      this.runbookId = defaults.runbookId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.tasks = defaults.tasks;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder executionWorkflowDetails(List<GetRunbookVersionsRunbookVersionCollectionItemExecutionWorkflowDetail> executionWorkflowDetails) {
            if (executionWorkflowDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "executionWorkflowDetails");
            }
            this.executionWorkflowDetails = executionWorkflowDetails;
            return this;
        }
        public Builder executionWorkflowDetails(GetRunbookVersionsRunbookVersionCollectionItemExecutionWorkflowDetail... executionWorkflowDetails) {
            return executionWorkflowDetails(List.of(executionWorkflowDetails));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder groups(List<GetRunbookVersionsRunbookVersionCollectionItemGroup> groups) {
            if (groups == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "groups");
            }
            this.groups = groups;
            return this;
        }
        public Builder groups(GetRunbookVersionsRunbookVersionCollectionItemGroup... groups) {
            return groups(List.of(groups));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isLatest(Boolean isLatest) {
            if (isLatest == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "isLatest");
            }
            this.isLatest = isLatest;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder rollbackWorkflowDetails(List<GetRunbookVersionsRunbookVersionCollectionItemRollbackWorkflowDetail> rollbackWorkflowDetails) {
            if (rollbackWorkflowDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "rollbackWorkflowDetails");
            }
            this.rollbackWorkflowDetails = rollbackWorkflowDetails;
            return this;
        }
        public Builder rollbackWorkflowDetails(GetRunbookVersionsRunbookVersionCollectionItemRollbackWorkflowDetail... rollbackWorkflowDetails) {
            return rollbackWorkflowDetails(List.of(rollbackWorkflowDetails));
        }
        @CustomType.Setter
        public Builder runbookId(String runbookId) {
            if (runbookId == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "runbookId");
            }
            this.runbookId = runbookId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder tasks(List<GetRunbookVersionsRunbookVersionCollectionItemTask> tasks) {
            if (tasks == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "tasks");
            }
            this.tasks = tasks;
            return this;
        }
        public Builder tasks(GetRunbookVersionsRunbookVersionCollectionItemTask... tasks) {
            return tasks(List.of(tasks));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetRunbookVersionsRunbookVersionCollectionItem build() {
            final var _resultValue = new GetRunbookVersionsRunbookVersionCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.executionWorkflowDetails = executionWorkflowDetails;
            _resultValue.freeformTags = freeformTags;
            _resultValue.groups = groups;
            _resultValue.id = id;
            _resultValue.isLatest = isLatest;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.name = name;
            _resultValue.rollbackWorkflowDetails = rollbackWorkflowDetails;
            _resultValue.runbookId = runbookId;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.tasks = tasks;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
