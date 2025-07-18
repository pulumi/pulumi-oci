// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetMaintenanceWindowResult {
    /**
     * @return Compartment OCID
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private String displayName;
    /**
     * @return Duration of the maintenance window. Specify how long the maintenance window remains open.
     * 
     */
    private String duration;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the resource.
     * 
     */
    private String id;
    /**
     * @return Does the maintenenace window cause outage? An outage indicates whether a maintenance window can consider operations that require downtime. It means a period when the application is not accessible.
     * 
     */
    private Boolean isOutage;
    /**
     * @return Is this a recurring maintenance window?
     * 
     */
    private Boolean isRecurring;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    private String maintenanceWindowId;
    /**
     * @return Recurrence rule specification if maintenance window recurring. Specify the frequency of running the maintenance window.
     * 
     */
    private String recurrences;
    /**
     * @return Associated region
     * 
     */
    private String resourceRegion;
    /**
     * @return The current state of the MaintenanceWindow.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return Specify the date and time of the day that the maintenance window starts.
     * 
     */
    private String timeScheduleStart;
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetMaintenanceWindowResult() {}
    /**
     * @return Compartment OCID
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
     * @return A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Duration of the maintenance window. Specify how long the maintenance window remains open.
     * 
     */
    public String duration() {
        return this.duration;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Does the maintenenace window cause outage? An outage indicates whether a maintenance window can consider operations that require downtime. It means a period when the application is not accessible.
     * 
     */
    public Boolean isOutage() {
        return this.isOutage;
    }
    /**
     * @return Is this a recurring maintenance window?
     * 
     */
    public Boolean isRecurring() {
        return this.isRecurring;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public String maintenanceWindowId() {
        return this.maintenanceWindowId;
    }
    /**
     * @return Recurrence rule specification if maintenance window recurring. Specify the frequency of running the maintenance window.
     * 
     */
    public String recurrences() {
        return this.recurrences;
    }
    /**
     * @return Associated region
     * 
     */
    public String resourceRegion() {
        return this.resourceRegion;
    }
    /**
     * @return The current state of the MaintenanceWindow.
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
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Specify the date and time of the day that the maintenance window starts.
     * 
     */
    public String timeScheduleStart() {
        return this.timeScheduleStart;
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

    public static Builder builder(GetMaintenanceWindowResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String duration;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isOutage;
        private Boolean isRecurring;
        private String lifecycleDetails;
        private String maintenanceWindowId;
        private String recurrences;
        private String resourceRegion;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeScheduleStart;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetMaintenanceWindowResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.duration = defaults.duration;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isOutage = defaults.isOutage;
    	      this.isRecurring = defaults.isRecurring;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.maintenanceWindowId = defaults.maintenanceWindowId;
    	      this.recurrences = defaults.recurrences;
    	      this.resourceRegion = defaults.resourceRegion;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeScheduleStart = defaults.timeScheduleStart;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder duration(String duration) {
            if (duration == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "duration");
            }
            this.duration = duration;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isOutage(Boolean isOutage) {
            if (isOutage == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "isOutage");
            }
            this.isOutage = isOutage;
            return this;
        }
        @CustomType.Setter
        public Builder isRecurring(Boolean isRecurring) {
            if (isRecurring == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "isRecurring");
            }
            this.isRecurring = isRecurring;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceWindowId(String maintenanceWindowId) {
            if (maintenanceWindowId == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "maintenanceWindowId");
            }
            this.maintenanceWindowId = maintenanceWindowId;
            return this;
        }
        @CustomType.Setter
        public Builder recurrences(String recurrences) {
            if (recurrences == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "recurrences");
            }
            this.recurrences = recurrences;
            return this;
        }
        @CustomType.Setter
        public Builder resourceRegion(String resourceRegion) {
            if (resourceRegion == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "resourceRegion");
            }
            this.resourceRegion = resourceRegion;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeScheduleStart(String timeScheduleStart) {
            if (timeScheduleStart == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "timeScheduleStart");
            }
            this.timeScheduleStart = timeScheduleStart;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetMaintenanceWindowResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetMaintenanceWindowResult build() {
            final var _resultValue = new GetMaintenanceWindowResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.duration = duration;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isOutage = isOutage;
            _resultValue.isRecurring = isRecurring;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.maintenanceWindowId = maintenanceWindowId;
            _resultValue.recurrences = recurrences;
            _resultValue.resourceRegion = resourceRegion;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeScheduleStart = timeScheduleStart;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
