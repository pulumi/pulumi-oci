// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMember;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction {
    /**
     * @return List of action members of this execution action.
     * 
     */
    private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMember> actionMembers;
    /**
     * @return Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
     * 
     */
    private Map<String,String> actionParams;
    /**
     * @return The action type of the execution action being performed
     * 
     */
    private String actionType;
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Description of the maintenance run.
     * 
     */
    private String description;
    /**
     * @return The user-friendly name for the maintenance run.
     * 
     */
    private String displayName;
    /**
     * @return The estimated time of the execution window in minutes.
     * 
     */
    private Integer estimatedTimeInMins;
    /**
     * @return The priority order of the execution action.
     * 
     */
    private Integer executionActionOrder;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
     * 
     */
    private String executionWindowId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the maintenance run.
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
     * 
     */
    private String lifecycleSubstate;
    /**
     * @return The state of the maintenance run history.
     * 
     */
    private String state;
    /**
     * @return The date and time the execution window was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The last date and time that the execution window was updated.
     * 
     */
    private String timeUpdated;
    /**
     * @return The total time taken by corresponding resource activity in minutes.
     * 
     */
    private Integer totalTimeTakenInMins;

    private GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction() {}
    /**
     * @return List of action members of this execution action.
     * 
     */
    public List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMember> actionMembers() {
        return this.actionMembers;
    }
    /**
     * @return Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
     * 
     */
    public Map<String,String> actionParams() {
        return this.actionParams;
    }
    /**
     * @return The action type of the execution action being performed
     * 
     */
    public String actionType() {
        return this.actionType;
    }
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description of the maintenance run.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The user-friendly name for the maintenance run.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The estimated time of the execution window in minutes.
     * 
     */
    public Integer estimatedTimeInMins() {
        return this.estimatedTimeInMins;
    }
    /**
     * @return The priority order of the execution action.
     * 
     */
    public Integer executionActionOrder() {
        return this.executionActionOrder;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
     * 
     */
    public String executionWindowId() {
        return this.executionWindowId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the maintenance run.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
     * 
     */
    public String lifecycleSubstate() {
        return this.lifecycleSubstate;
    }
    /**
     * @return The state of the maintenance run history.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the execution window was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The last date and time that the execution window was updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The total time taken by corresponding resource activity in minutes.
     * 
     */
    public Integer totalTimeTakenInMins() {
        return this.totalTimeTakenInMins;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMember> actionMembers;
        private Map<String,String> actionParams;
        private String actionType;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Integer estimatedTimeInMins;
        private Integer executionActionOrder;
        private String executionWindowId;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String lifecycleSubstate;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private Integer totalTimeTakenInMins;
        public Builder() {}
        public Builder(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actionMembers = defaults.actionMembers;
    	      this.actionParams = defaults.actionParams;
    	      this.actionType = defaults.actionType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.estimatedTimeInMins = defaults.estimatedTimeInMins;
    	      this.executionActionOrder = defaults.executionActionOrder;
    	      this.executionWindowId = defaults.executionWindowId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.lifecycleSubstate = defaults.lifecycleSubstate;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.totalTimeTakenInMins = defaults.totalTimeTakenInMins;
        }

        @CustomType.Setter
        public Builder actionMembers(List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMember> actionMembers) {
            if (actionMembers == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "actionMembers");
            }
            this.actionMembers = actionMembers;
            return this;
        }
        public Builder actionMembers(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionActionActionMember... actionMembers) {
            return actionMembers(List.of(actionMembers));
        }
        @CustomType.Setter
        public Builder actionParams(Map<String,String> actionParams) {
            if (actionParams == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "actionParams");
            }
            this.actionParams = actionParams;
            return this;
        }
        @CustomType.Setter
        public Builder actionType(String actionType) {
            if (actionType == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "actionType");
            }
            this.actionType = actionType;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder estimatedTimeInMins(Integer estimatedTimeInMins) {
            if (estimatedTimeInMins == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "estimatedTimeInMins");
            }
            this.estimatedTimeInMins = estimatedTimeInMins;
            return this;
        }
        @CustomType.Setter
        public Builder executionActionOrder(Integer executionActionOrder) {
            if (executionActionOrder == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "executionActionOrder");
            }
            this.executionActionOrder = executionActionOrder;
            return this;
        }
        @CustomType.Setter
        public Builder executionWindowId(String executionWindowId) {
            if (executionWindowId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "executionWindowId");
            }
            this.executionWindowId = executionWindowId;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleSubstate(String lifecycleSubstate) {
            if (lifecycleSubstate == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "lifecycleSubstate");
            }
            this.lifecycleSubstate = lifecycleSubstate;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder totalTimeTakenInMins(Integer totalTimeTakenInMins) {
            if (totalTimeTakenInMins == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction", "totalTimeTakenInMins");
            }
            this.totalTimeTakenInMins = totalTimeTakenInMins;
            return this;
        }
        public GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction build() {
            final var _resultValue = new GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryExecutionAction();
            _resultValue.actionMembers = actionMembers;
            _resultValue.actionParams = actionParams;
            _resultValue.actionType = actionType;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.estimatedTimeInMins = estimatedTimeInMins;
            _resultValue.executionActionOrder = executionActionOrder;
            _resultValue.executionWindowId = executionWindowId;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.lifecycleSubstate = lifecycleSubstate;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.totalTimeTakenInMins = totalTimeTakenInMins;
            return _resultValue;
        }
    }
}
