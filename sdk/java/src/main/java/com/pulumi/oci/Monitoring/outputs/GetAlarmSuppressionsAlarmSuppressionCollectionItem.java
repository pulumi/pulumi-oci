// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Monitoring.outputs.GetAlarmSuppressionsAlarmSuppressionCollectionItemAlarmSuppressionTarget;
import com.pulumi.oci.Monitoring.outputs.GetAlarmSuppressionsAlarmSuppressionCollectionItemSuppressionCondition;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAlarmSuppressionsAlarmSuppressionCollectionItem {
    /**
     * @return The target of the alarm suppression.
     * 
     */
    private List<GetAlarmSuppressionsAlarmSuppressionCollectionItemAlarmSuppressionTarget> alarmSuppressionTargets;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for searching.  Use the tenancy OCID to search in the root compartment.
     * 
     * If targetType is not specified, searches all suppressions defined under the compartment.  If targetType is `COMPARTMENT`, searches suppressions in the specified compartment only.
     * 
     * Example: `ocid1.compartment.oc1..exampleuniqueID`
     * 
     */
    private String compartmentId;
    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Human-readable reason for this alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return Configured dimension filter for suppressing alarm state entries that include the set of specified dimension key-value pairs.  Example: `{&#34;resourceId&#34;: &#34;instance.region1.phx.exampleuniqueID&#34;}`
     * 
     */
    private Map<String,String> dimensions;
    /**
     * @return A filter to return only resources that match the given display name exactly. Use this filter to list an alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm suppression.
     * 
     */
    private String id;
    /**
     * @return The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
     * 
     */
    private String level;
    /**
     * @return A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
     * 
     */
    private String state;
    /**
     * @return Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
     * 
     */
    private List<GetAlarmSuppressionsAlarmSuppressionCollectionItemSuppressionCondition> suppressionConditions;
    /**
     * @return The date and time the alarm suppression was created. Format defined by RFC3339.  Example: `2018-02-01T01:02:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2018-02-01T01:02:29.600Z`
     * 
     */
    private String timeSuppressFrom;
    /**
     * @return The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2018-02-01T02:02:29.600Z`
     * 
     */
    private String timeSuppressUntil;
    /**
     * @return The date and time the alarm suppression was last updated (deleted). Format defined by RFC3339.  Example: `2018-02-03T01:02:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetAlarmSuppressionsAlarmSuppressionCollectionItem() {}
    /**
     * @return The target of the alarm suppression.
     * 
     */
    public List<GetAlarmSuppressionsAlarmSuppressionCollectionItemAlarmSuppressionTarget> alarmSuppressionTargets() {
        return this.alarmSuppressionTargets;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for searching.  Use the tenancy OCID to search in the root compartment.
     * 
     * If targetType is not specified, searches all suppressions defined under the compartment.  If targetType is `COMPARTMENT`, searches suppressions in the specified compartment only.
     * 
     * Example: `ocid1.compartment.oc1..exampleuniqueID`
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Human-readable reason for this alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Configured dimension filter for suppressing alarm state entries that include the set of specified dimension key-value pairs.  Example: `{&#34;resourceId&#34;: &#34;instance.region1.phx.exampleuniqueID&#34;}`
     * 
     */
    public Map<String,String> dimensions() {
        return this.dimensions;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly. Use this filter to list an alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm suppression.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
     * 
     */
    public String level() {
        return this.level;
    }
    /**
     * @return A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
     * 
     */
    public List<GetAlarmSuppressionsAlarmSuppressionCollectionItemSuppressionCondition> suppressionConditions() {
        return this.suppressionConditions;
    }
    /**
     * @return The date and time the alarm suppression was created. Format defined by RFC3339.  Example: `2018-02-01T01:02:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2018-02-01T01:02:29.600Z`
     * 
     */
    public String timeSuppressFrom() {
        return this.timeSuppressFrom;
    }
    /**
     * @return The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2018-02-01T02:02:29.600Z`
     * 
     */
    public String timeSuppressUntil() {
        return this.timeSuppressUntil;
    }
    /**
     * @return The date and time the alarm suppression was last updated (deleted). Format defined by RFC3339.  Example: `2018-02-03T01:02:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlarmSuppressionsAlarmSuppressionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAlarmSuppressionsAlarmSuppressionCollectionItemAlarmSuppressionTarget> alarmSuppressionTargets;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private Map<String,String> dimensions;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String level;
        private String state;
        private List<GetAlarmSuppressionsAlarmSuppressionCollectionItemSuppressionCondition> suppressionConditions;
        private String timeCreated;
        private String timeSuppressFrom;
        private String timeSuppressUntil;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetAlarmSuppressionsAlarmSuppressionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alarmSuppressionTargets = defaults.alarmSuppressionTargets;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.dimensions = defaults.dimensions;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.level = defaults.level;
    	      this.state = defaults.state;
    	      this.suppressionConditions = defaults.suppressionConditions;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeSuppressFrom = defaults.timeSuppressFrom;
    	      this.timeSuppressUntil = defaults.timeSuppressUntil;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder alarmSuppressionTargets(List<GetAlarmSuppressionsAlarmSuppressionCollectionItemAlarmSuppressionTarget> alarmSuppressionTargets) {
            if (alarmSuppressionTargets == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "alarmSuppressionTargets");
            }
            this.alarmSuppressionTargets = alarmSuppressionTargets;
            return this;
        }
        public Builder alarmSuppressionTargets(GetAlarmSuppressionsAlarmSuppressionCollectionItemAlarmSuppressionTarget... alarmSuppressionTargets) {
            return alarmSuppressionTargets(List.of(alarmSuppressionTargets));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder dimensions(Map<String,String> dimensions) {
            if (dimensions == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "dimensions");
            }
            this.dimensions = dimensions;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder level(String level) {
            if (level == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "level");
            }
            this.level = level;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder suppressionConditions(List<GetAlarmSuppressionsAlarmSuppressionCollectionItemSuppressionCondition> suppressionConditions) {
            if (suppressionConditions == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "suppressionConditions");
            }
            this.suppressionConditions = suppressionConditions;
            return this;
        }
        public Builder suppressionConditions(GetAlarmSuppressionsAlarmSuppressionCollectionItemSuppressionCondition... suppressionConditions) {
            return suppressionConditions(List.of(suppressionConditions));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeSuppressFrom(String timeSuppressFrom) {
            if (timeSuppressFrom == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "timeSuppressFrom");
            }
            this.timeSuppressFrom = timeSuppressFrom;
            return this;
        }
        @CustomType.Setter
        public Builder timeSuppressUntil(String timeSuppressUntil) {
            if (timeSuppressUntil == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "timeSuppressUntil");
            }
            this.timeSuppressUntil = timeSuppressUntil;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetAlarmSuppressionsAlarmSuppressionCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetAlarmSuppressionsAlarmSuppressionCollectionItem build() {
            final var _resultValue = new GetAlarmSuppressionsAlarmSuppressionCollectionItem();
            _resultValue.alarmSuppressionTargets = alarmSuppressionTargets;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.dimensions = dimensions;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.level = level;
            _resultValue.state = state;
            _resultValue.suppressionConditions = suppressionConditions;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeSuppressFrom = timeSuppressFrom;
            _resultValue.timeSuppressUntil = timeSuppressUntil;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
