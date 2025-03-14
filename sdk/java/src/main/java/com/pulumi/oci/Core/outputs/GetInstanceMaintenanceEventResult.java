// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInstanceMaintenanceEventResult {
    /**
     * @return Additional details of the maintenance in the form of json.
     * 
     */
    private Map<String,String> additionalDetails;
    private String alternativeResolutionAction;
    /**
     * @return These are alternative actions to the requested instanceAction that can be taken to resolve the Maintenance.
     * 
     */
    private List<String> alternativeResolutionActions;
    /**
     * @return For Instances that have local storage, this field is set to true when local storage will be deleted as a result of the Maintenance.
     * 
     */
    private Boolean canDeleteLocalStorage;
    /**
     * @return Indicates if this MaintenanceEvent is capable of being rescheduled up to the timeHardDueDate.
     * 
     */
    private Boolean canReschedule;
    /**
     * @return The OCID of the compartment that contains the instance.
     * 
     */
    private String compartmentId;
    /**
     * @return A unique identifier that will group Instances that have a relationship with one another and must be scheduled together for the Maintenance to proceed. Any Instances that have a relationship with one another from a Maintenance perspective will have a matching correlationToken.
     * 
     */
    private String correlationToken;
    /**
     * @return The creator of the maintenance event.
     * 
     */
    private String createdBy;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return It is the descriptive information about the maintenance taking place on the customer instance.
     * 
     */
    private String description;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return This is the estimated duration of the Maintenance, once the Maintenance has entered the STARTED state.
     * 
     */
    private String estimatedDuration;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance event.
     * 
     */
    private String id;
    /**
     * @return This is the action that will be performed on the Instance by Oracle Cloud Infrastructure when the Maintenance begins.
     * 
     */
    private String instanceAction;
    /**
     * @return The OCID of the instance.
     * 
     */
    private String instanceId;
    private String instanceMaintenanceEventId;
    /**
     * @return This indicates the priority and allowed actions for this Maintenance. Higher priority forms of Maintenance have tighter restrictions and may not be rescheduled, while lower priority/severity Maintenance can be rescheduled, deferred, or even cancelled. Please see the [Instance Maintenance](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/placeholder.htm) documentation for details.
     * 
     */
    private String maintenanceCategory;
    /**
     * @return This is the reason that Maintenance is being performed. See [Instance Maintenance](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/placeholder.htm) documentation for details.
     * 
     */
    private String maintenanceReason;
    /**
     * @return The duration of the time window Maintenance is scheduled to begin within.
     * 
     */
    private String startWindowDuration;
    /**
     * @return The current state of the maintenance event.
     * 
     */
    private String state;
    /**
     * @return The date and time the maintenance event was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time at which the Maintenance actually finished.
     * 
     */
    private String timeFinished;
    /**
     * @return It is the scheduled hard due date and time of the maintenance event. The maintenance event will happen at this time and the due date will not be extended.
     * 
     */
    private String timeHardDueDate;
    /**
     * @return The time at which the Maintenance actually started.
     * 
     */
    private String timeStarted;
    /**
     * @return The beginning of the time window when Maintenance is scheduled to begin. The Maintenance will not begin before this time.
     * 
     */
    private String timeWindowStart;

    private GetInstanceMaintenanceEventResult() {}
    /**
     * @return Additional details of the maintenance in the form of json.
     * 
     */
    public Map<String,String> additionalDetails() {
        return this.additionalDetails;
    }
    public String alternativeResolutionAction() {
        return this.alternativeResolutionAction;
    }
    /**
     * @return These are alternative actions to the requested instanceAction that can be taken to resolve the Maintenance.
     * 
     */
    public List<String> alternativeResolutionActions() {
        return this.alternativeResolutionActions;
    }
    /**
     * @return For Instances that have local storage, this field is set to true when local storage will be deleted as a result of the Maintenance.
     * 
     */
    public Boolean canDeleteLocalStorage() {
        return this.canDeleteLocalStorage;
    }
    /**
     * @return Indicates if this MaintenanceEvent is capable of being rescheduled up to the timeHardDueDate.
     * 
     */
    public Boolean canReschedule() {
        return this.canReschedule;
    }
    /**
     * @return The OCID of the compartment that contains the instance.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A unique identifier that will group Instances that have a relationship with one another and must be scheduled together for the Maintenance to proceed. Any Instances that have a relationship with one another from a Maintenance perspective will have a matching correlationToken.
     * 
     */
    public String correlationToken() {
        return this.correlationToken;
    }
    /**
     * @return The creator of the maintenance event.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return It is the descriptive information about the maintenance taking place on the customer instance.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return This is the estimated duration of the Maintenance, once the Maintenance has entered the STARTED state.
     * 
     */
    public String estimatedDuration() {
        return this.estimatedDuration;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance event.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return This is the action that will be performed on the Instance by Oracle Cloud Infrastructure when the Maintenance begins.
     * 
     */
    public String instanceAction() {
        return this.instanceAction;
    }
    /**
     * @return The OCID of the instance.
     * 
     */
    public String instanceId() {
        return this.instanceId;
    }
    public String instanceMaintenanceEventId() {
        return this.instanceMaintenanceEventId;
    }
    /**
     * @return This indicates the priority and allowed actions for this Maintenance. Higher priority forms of Maintenance have tighter restrictions and may not be rescheduled, while lower priority/severity Maintenance can be rescheduled, deferred, or even cancelled. Please see the [Instance Maintenance](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/placeholder.htm) documentation for details.
     * 
     */
    public String maintenanceCategory() {
        return this.maintenanceCategory;
    }
    /**
     * @return This is the reason that Maintenance is being performed. See [Instance Maintenance](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/placeholder.htm) documentation for details.
     * 
     */
    public String maintenanceReason() {
        return this.maintenanceReason;
    }
    /**
     * @return The duration of the time window Maintenance is scheduled to begin within.
     * 
     */
    public String startWindowDuration() {
        return this.startWindowDuration;
    }
    /**
     * @return The current state of the maintenance event.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the maintenance event was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time at which the Maintenance actually finished.
     * 
     */
    public String timeFinished() {
        return this.timeFinished;
    }
    /**
     * @return It is the scheduled hard due date and time of the maintenance event. The maintenance event will happen at this time and the due date will not be extended.
     * 
     */
    public String timeHardDueDate() {
        return this.timeHardDueDate;
    }
    /**
     * @return The time at which the Maintenance actually started.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return The beginning of the time window when Maintenance is scheduled to begin. The Maintenance will not begin before this time.
     * 
     */
    public String timeWindowStart() {
        return this.timeWindowStart;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceMaintenanceEventResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,String> additionalDetails;
        private String alternativeResolutionAction;
        private List<String> alternativeResolutionActions;
        private Boolean canDeleteLocalStorage;
        private Boolean canReschedule;
        private String compartmentId;
        private String correlationToken;
        private String createdBy;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String estimatedDuration;
        private Map<String,String> freeformTags;
        private String id;
        private String instanceAction;
        private String instanceId;
        private String instanceMaintenanceEventId;
        private String maintenanceCategory;
        private String maintenanceReason;
        private String startWindowDuration;
        private String state;
        private String timeCreated;
        private String timeFinished;
        private String timeHardDueDate;
        private String timeStarted;
        private String timeWindowStart;
        public Builder() {}
        public Builder(GetInstanceMaintenanceEventResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalDetails = defaults.additionalDetails;
    	      this.alternativeResolutionAction = defaults.alternativeResolutionAction;
    	      this.alternativeResolutionActions = defaults.alternativeResolutionActions;
    	      this.canDeleteLocalStorage = defaults.canDeleteLocalStorage;
    	      this.canReschedule = defaults.canReschedule;
    	      this.compartmentId = defaults.compartmentId;
    	      this.correlationToken = defaults.correlationToken;
    	      this.createdBy = defaults.createdBy;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.estimatedDuration = defaults.estimatedDuration;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.instanceAction = defaults.instanceAction;
    	      this.instanceId = defaults.instanceId;
    	      this.instanceMaintenanceEventId = defaults.instanceMaintenanceEventId;
    	      this.maintenanceCategory = defaults.maintenanceCategory;
    	      this.maintenanceReason = defaults.maintenanceReason;
    	      this.startWindowDuration = defaults.startWindowDuration;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeFinished = defaults.timeFinished;
    	      this.timeHardDueDate = defaults.timeHardDueDate;
    	      this.timeStarted = defaults.timeStarted;
    	      this.timeWindowStart = defaults.timeWindowStart;
        }

        @CustomType.Setter
        public Builder additionalDetails(Map<String,String> additionalDetails) {
            if (additionalDetails == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "additionalDetails");
            }
            this.additionalDetails = additionalDetails;
            return this;
        }
        @CustomType.Setter
        public Builder alternativeResolutionAction(String alternativeResolutionAction) {
            if (alternativeResolutionAction == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "alternativeResolutionAction");
            }
            this.alternativeResolutionAction = alternativeResolutionAction;
            return this;
        }
        @CustomType.Setter
        public Builder alternativeResolutionActions(List<String> alternativeResolutionActions) {
            if (alternativeResolutionActions == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "alternativeResolutionActions");
            }
            this.alternativeResolutionActions = alternativeResolutionActions;
            return this;
        }
        public Builder alternativeResolutionActions(String... alternativeResolutionActions) {
            return alternativeResolutionActions(List.of(alternativeResolutionActions));
        }
        @CustomType.Setter
        public Builder canDeleteLocalStorage(Boolean canDeleteLocalStorage) {
            if (canDeleteLocalStorage == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "canDeleteLocalStorage");
            }
            this.canDeleteLocalStorage = canDeleteLocalStorage;
            return this;
        }
        @CustomType.Setter
        public Builder canReschedule(Boolean canReschedule) {
            if (canReschedule == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "canReschedule");
            }
            this.canReschedule = canReschedule;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder correlationToken(String correlationToken) {
            if (correlationToken == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "correlationToken");
            }
            this.correlationToken = correlationToken;
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            if (createdBy == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "createdBy");
            }
            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder estimatedDuration(String estimatedDuration) {
            if (estimatedDuration == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "estimatedDuration");
            }
            this.estimatedDuration = estimatedDuration;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceAction(String instanceAction) {
            if (instanceAction == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "instanceAction");
            }
            this.instanceAction = instanceAction;
            return this;
        }
        @CustomType.Setter
        public Builder instanceId(String instanceId) {
            if (instanceId == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "instanceId");
            }
            this.instanceId = instanceId;
            return this;
        }
        @CustomType.Setter
        public Builder instanceMaintenanceEventId(String instanceMaintenanceEventId) {
            if (instanceMaintenanceEventId == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "instanceMaintenanceEventId");
            }
            this.instanceMaintenanceEventId = instanceMaintenanceEventId;
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceCategory(String maintenanceCategory) {
            if (maintenanceCategory == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "maintenanceCategory");
            }
            this.maintenanceCategory = maintenanceCategory;
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceReason(String maintenanceReason) {
            if (maintenanceReason == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "maintenanceReason");
            }
            this.maintenanceReason = maintenanceReason;
            return this;
        }
        @CustomType.Setter
        public Builder startWindowDuration(String startWindowDuration) {
            if (startWindowDuration == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "startWindowDuration");
            }
            this.startWindowDuration = startWindowDuration;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeFinished(String timeFinished) {
            if (timeFinished == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "timeFinished");
            }
            this.timeFinished = timeFinished;
            return this;
        }
        @CustomType.Setter
        public Builder timeHardDueDate(String timeHardDueDate) {
            if (timeHardDueDate == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "timeHardDueDate");
            }
            this.timeHardDueDate = timeHardDueDate;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            if (timeStarted == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "timeStarted");
            }
            this.timeStarted = timeStarted;
            return this;
        }
        @CustomType.Setter
        public Builder timeWindowStart(String timeWindowStart) {
            if (timeWindowStart == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventResult", "timeWindowStart");
            }
            this.timeWindowStart = timeWindowStart;
            return this;
        }
        public GetInstanceMaintenanceEventResult build() {
            final var _resultValue = new GetInstanceMaintenanceEventResult();
            _resultValue.additionalDetails = additionalDetails;
            _resultValue.alternativeResolutionAction = alternativeResolutionAction;
            _resultValue.alternativeResolutionActions = alternativeResolutionActions;
            _resultValue.canDeleteLocalStorage = canDeleteLocalStorage;
            _resultValue.canReschedule = canReschedule;
            _resultValue.compartmentId = compartmentId;
            _resultValue.correlationToken = correlationToken;
            _resultValue.createdBy = createdBy;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.estimatedDuration = estimatedDuration;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.instanceAction = instanceAction;
            _resultValue.instanceId = instanceId;
            _resultValue.instanceMaintenanceEventId = instanceMaintenanceEventId;
            _resultValue.maintenanceCategory = maintenanceCategory;
            _resultValue.maintenanceReason = maintenanceReason;
            _resultValue.startWindowDuration = startWindowDuration;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeFinished = timeFinished;
            _resultValue.timeHardDueDate = timeHardDueDate;
            _resultValue.timeStarted = timeStarted;
            _resultValue.timeWindowStart = timeWindowStart;
            return _resultValue;
        }
    }
}
