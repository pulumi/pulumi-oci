// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetSchedulingPolicySchedulingWindowWindowPreference;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSchedulingPolicySchedulingWindowResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The user-friendly name for the Scheduling Window. The name does not need to be unique.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Policy.
     * 
     */
    private String schedulingPolicyId;
    private String schedulingWindowId;
    /**
     * @return The current state of the Scheduling Window. Valid states are CREATING, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    private String state;
    /**
     * @return The date and time the Scheduling Window was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time of the next upcoming window associated within the schedulingWindow is planned to start.
     * 
     */
    private String timeNextSchedulingWindowStarts;
    /**
     * @return The last date and time that the Scheduling Window was updated.
     * 
     */
    private String timeUpdated;
    /**
     * @return The Single Scheduling Window details.
     * 
     */
    private List<GetSchedulingPolicySchedulingWindowWindowPreference> windowPreferences;

    private GetSchedulingPolicySchedulingWindowResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
     * @return The user-friendly name for the Scheduling Window. The name does not need to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Policy.
     * 
     */
    public String schedulingPolicyId() {
        return this.schedulingPolicyId;
    }
    public String schedulingWindowId() {
        return this.schedulingWindowId;
    }
    /**
     * @return The current state of the Scheduling Window. Valid states are CREATING, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the Scheduling Window was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time of the next upcoming window associated within the schedulingWindow is planned to start.
     * 
     */
    public String timeNextSchedulingWindowStarts() {
        return this.timeNextSchedulingWindowStarts;
    }
    /**
     * @return The last date and time that the Scheduling Window was updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The Single Scheduling Window details.
     * 
     */
    public List<GetSchedulingPolicySchedulingWindowWindowPreference> windowPreferences() {
        return this.windowPreferences;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulingPolicySchedulingWindowResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String schedulingPolicyId;
        private String schedulingWindowId;
        private String state;
        private String timeCreated;
        private String timeNextSchedulingWindowStarts;
        private String timeUpdated;
        private List<GetSchedulingPolicySchedulingWindowWindowPreference> windowPreferences;
        public Builder() {}
        public Builder(GetSchedulingPolicySchedulingWindowResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.schedulingPolicyId = defaults.schedulingPolicyId;
    	      this.schedulingWindowId = defaults.schedulingWindowId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeNextSchedulingWindowStarts = defaults.timeNextSchedulingWindowStarts;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.windowPreferences = defaults.windowPreferences;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder schedulingPolicyId(String schedulingPolicyId) {
            if (schedulingPolicyId == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "schedulingPolicyId");
            }
            this.schedulingPolicyId = schedulingPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder schedulingWindowId(String schedulingWindowId) {
            if (schedulingWindowId == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "schedulingWindowId");
            }
            this.schedulingWindowId = schedulingWindowId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeNextSchedulingWindowStarts(String timeNextSchedulingWindowStarts) {
            if (timeNextSchedulingWindowStarts == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "timeNextSchedulingWindowStarts");
            }
            this.timeNextSchedulingWindowStarts = timeNextSchedulingWindowStarts;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder windowPreferences(List<GetSchedulingPolicySchedulingWindowWindowPreference> windowPreferences) {
            if (windowPreferences == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPolicySchedulingWindowResult", "windowPreferences");
            }
            this.windowPreferences = windowPreferences;
            return this;
        }
        public Builder windowPreferences(GetSchedulingPolicySchedulingWindowWindowPreference... windowPreferences) {
            return windowPreferences(List.of(windowPreferences));
        }
        public GetSchedulingPolicySchedulingWindowResult build() {
            final var _resultValue = new GetSchedulingPolicySchedulingWindowResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.schedulingPolicyId = schedulingPolicyId;
            _resultValue.schedulingWindowId = schedulingWindowId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeNextSchedulingWindowStarts = timeNextSchedulingWindowStarts;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.windowPreferences = windowPreferences;
            return _resultValue;
        }
    }
}
