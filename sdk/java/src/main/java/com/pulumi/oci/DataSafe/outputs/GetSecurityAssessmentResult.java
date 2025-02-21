// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatistic;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentResult {
    /**
     * @return The OCID of the compartment that contains the security assessment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description of the security assessment.
     * 
     */
    private String description;
    /**
     * @return The display name of the security assessment.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the security assessment.
     * 
     */
    private String id;
    /**
     * @return List containing maps as values. Example: `{&#34;Operations&#34;: [ {&#34;CostCenter&#34;: &#34;42&#34;} ] }`
     * 
     */
    private List<String> ignoredAssessmentIds;
    /**
     * @return List containing maps as values. Example: `{&#34;Operations&#34;: [ {&#34;CostCenter&#34;: &#34;42&#34;} ] }`
     * 
     */
    private List<String> ignoredTargets;
    /**
     * @return Indicates whether the assessment is scheduled to run.
     * 
     */
    private Boolean isAssessmentScheduled;
    /**
     * @return Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
     * 
     */
    private Boolean isBaseline;
    /**
     * @return Indicates whether or not the security assessment deviates from the baseline.
     * 
     */
    private Boolean isDeviatedFromBaseline;
    /**
     * @return The OCID of the baseline against which the latest security assessment was compared.
     * 
     */
    private String lastComparedBaselineId;
    /**
     * @return Details about the current state of the security assessment.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The summary of findings for the security assessment.
     * 
     */
    private String link;
    /**
     * @return Schedule of the assessment that runs periodically in the specified format: - &lt;version-string&gt;;&lt;version-specific-schedule&gt;
     * 
     */
    private String schedule;
    /**
     * @return The OCID of the security assessment that is responsible for creating this scheduled save assessment.
     * 
     */
    private String scheduleSecurityAssessmentId;
    private String securityAssessmentId;
    /**
     * @return The current state of the security assessment.
     * 
     */
    private String state;
    /**
     * @return Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
     * 
     */
    private List<GetSecurityAssessmentStatistic> statistics;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    private String targetId;
    /**
     * @return Array of database target OCIDs.
     * 
     */
    private List<String> targetIds;
    /**
     * @return The version of the target database.
     * 
     */
    private String targetVersion;
    /**
     * @return The date and time the security assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the security assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeLastAssessed;
    /**
     * @return The date and time the security assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeUpdated;
    /**
     * @return Indicates whether the security assessment was created by system or by a user.
     * 
     */
    private String triggeredBy;
    /**
     * @return The type of this security assessment. The possible types are:
     * 
     */
    private String type;

    private GetSecurityAssessmentResult() {}
    /**
     * @return The OCID of the compartment that contains the security assessment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the security assessment.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The display name of the security assessment.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the security assessment.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return List containing maps as values. Example: `{&#34;Operations&#34;: [ {&#34;CostCenter&#34;: &#34;42&#34;} ] }`
     * 
     */
    public List<String> ignoredAssessmentIds() {
        return this.ignoredAssessmentIds;
    }
    /**
     * @return List containing maps as values. Example: `{&#34;Operations&#34;: [ {&#34;CostCenter&#34;: &#34;42&#34;} ] }`
     * 
     */
    public List<String> ignoredTargets() {
        return this.ignoredTargets;
    }
    /**
     * @return Indicates whether the assessment is scheduled to run.
     * 
     */
    public Boolean isAssessmentScheduled() {
        return this.isAssessmentScheduled;
    }
    /**
     * @return Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
     * 
     */
    public Boolean isBaseline() {
        return this.isBaseline;
    }
    /**
     * @return Indicates whether or not the security assessment deviates from the baseline.
     * 
     */
    public Boolean isDeviatedFromBaseline() {
        return this.isDeviatedFromBaseline;
    }
    /**
     * @return The OCID of the baseline against which the latest security assessment was compared.
     * 
     */
    public String lastComparedBaselineId() {
        return this.lastComparedBaselineId;
    }
    /**
     * @return Details about the current state of the security assessment.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The summary of findings for the security assessment.
     * 
     */
    public String link() {
        return this.link;
    }
    /**
     * @return Schedule of the assessment that runs periodically in the specified format: - &lt;version-string&gt;;&lt;version-specific-schedule&gt;
     * 
     */
    public String schedule() {
        return this.schedule;
    }
    /**
     * @return The OCID of the security assessment that is responsible for creating this scheduled save assessment.
     * 
     */
    public String scheduleSecurityAssessmentId() {
        return this.scheduleSecurityAssessmentId;
    }
    public String securityAssessmentId() {
        return this.securityAssessmentId;
    }
    /**
     * @return The current state of the security assessment.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
     * 
     */
    public List<GetSecurityAssessmentStatistic> statistics() {
        return this.statistics;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    public String targetId() {
        return this.targetId;
    }
    /**
     * @return Array of database target OCIDs.
     * 
     */
    public List<String> targetIds() {
        return this.targetIds;
    }
    /**
     * @return The version of the target database.
     * 
     */
    public String targetVersion() {
        return this.targetVersion;
    }
    /**
     * @return The date and time the security assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the security assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeLastAssessed() {
        return this.timeLastAssessed;
    }
    /**
     * @return The date and time the security assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Indicates whether the security assessment was created by system or by a user.
     * 
     */
    public String triggeredBy() {
        return this.triggeredBy;
    }
    /**
     * @return The type of this security assessment. The possible types are:
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private List<String> ignoredAssessmentIds;
        private List<String> ignoredTargets;
        private Boolean isAssessmentScheduled;
        private Boolean isBaseline;
        private Boolean isDeviatedFromBaseline;
        private String lastComparedBaselineId;
        private String lifecycleDetails;
        private String link;
        private String schedule;
        private String scheduleSecurityAssessmentId;
        private String securityAssessmentId;
        private String state;
        private List<GetSecurityAssessmentStatistic> statistics;
        private Map<String,String> systemTags;
        private String targetId;
        private List<String> targetIds;
        private String targetVersion;
        private String timeCreated;
        private String timeLastAssessed;
        private String timeUpdated;
        private String triggeredBy;
        private String type;
        public Builder() {}
        public Builder(GetSecurityAssessmentResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.ignoredAssessmentIds = defaults.ignoredAssessmentIds;
    	      this.ignoredTargets = defaults.ignoredTargets;
    	      this.isAssessmentScheduled = defaults.isAssessmentScheduled;
    	      this.isBaseline = defaults.isBaseline;
    	      this.isDeviatedFromBaseline = defaults.isDeviatedFromBaseline;
    	      this.lastComparedBaselineId = defaults.lastComparedBaselineId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.link = defaults.link;
    	      this.schedule = defaults.schedule;
    	      this.scheduleSecurityAssessmentId = defaults.scheduleSecurityAssessmentId;
    	      this.securityAssessmentId = defaults.securityAssessmentId;
    	      this.state = defaults.state;
    	      this.statistics = defaults.statistics;
    	      this.systemTags = defaults.systemTags;
    	      this.targetId = defaults.targetId;
    	      this.targetIds = defaults.targetIds;
    	      this.targetVersion = defaults.targetVersion;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastAssessed = defaults.timeLastAssessed;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.triggeredBy = defaults.triggeredBy;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ignoredAssessmentIds(List<String> ignoredAssessmentIds) {
            if (ignoredAssessmentIds == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "ignoredAssessmentIds");
            }
            this.ignoredAssessmentIds = ignoredAssessmentIds;
            return this;
        }
        public Builder ignoredAssessmentIds(String... ignoredAssessmentIds) {
            return ignoredAssessmentIds(List.of(ignoredAssessmentIds));
        }
        @CustomType.Setter
        public Builder ignoredTargets(List<String> ignoredTargets) {
            if (ignoredTargets == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "ignoredTargets");
            }
            this.ignoredTargets = ignoredTargets;
            return this;
        }
        public Builder ignoredTargets(String... ignoredTargets) {
            return ignoredTargets(List.of(ignoredTargets));
        }
        @CustomType.Setter
        public Builder isAssessmentScheduled(Boolean isAssessmentScheduled) {
            if (isAssessmentScheduled == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "isAssessmentScheduled");
            }
            this.isAssessmentScheduled = isAssessmentScheduled;
            return this;
        }
        @CustomType.Setter
        public Builder isBaseline(Boolean isBaseline) {
            if (isBaseline == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "isBaseline");
            }
            this.isBaseline = isBaseline;
            return this;
        }
        @CustomType.Setter
        public Builder isDeviatedFromBaseline(Boolean isDeviatedFromBaseline) {
            if (isDeviatedFromBaseline == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "isDeviatedFromBaseline");
            }
            this.isDeviatedFromBaseline = isDeviatedFromBaseline;
            return this;
        }
        @CustomType.Setter
        public Builder lastComparedBaselineId(String lastComparedBaselineId) {
            if (lastComparedBaselineId == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "lastComparedBaselineId");
            }
            this.lastComparedBaselineId = lastComparedBaselineId;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder link(String link) {
            if (link == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "link");
            }
            this.link = link;
            return this;
        }
        @CustomType.Setter
        public Builder schedule(String schedule) {
            if (schedule == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "schedule");
            }
            this.schedule = schedule;
            return this;
        }
        @CustomType.Setter
        public Builder scheduleSecurityAssessmentId(String scheduleSecurityAssessmentId) {
            if (scheduleSecurityAssessmentId == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "scheduleSecurityAssessmentId");
            }
            this.scheduleSecurityAssessmentId = scheduleSecurityAssessmentId;
            return this;
        }
        @CustomType.Setter
        public Builder securityAssessmentId(String securityAssessmentId) {
            if (securityAssessmentId == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "securityAssessmentId");
            }
            this.securityAssessmentId = securityAssessmentId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder statistics(List<GetSecurityAssessmentStatistic> statistics) {
            if (statistics == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "statistics");
            }
            this.statistics = statistics;
            return this;
        }
        public Builder statistics(GetSecurityAssessmentStatistic... statistics) {
            return statistics(List.of(statistics));
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            if (targetId == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "targetId");
            }
            this.targetId = targetId;
            return this;
        }
        @CustomType.Setter
        public Builder targetIds(List<String> targetIds) {
            if (targetIds == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "targetIds");
            }
            this.targetIds = targetIds;
            return this;
        }
        public Builder targetIds(String... targetIds) {
            return targetIds(List.of(targetIds));
        }
        @CustomType.Setter
        public Builder targetVersion(String targetVersion) {
            if (targetVersion == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "targetVersion");
            }
            this.targetVersion = targetVersion;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastAssessed(String timeLastAssessed) {
            if (timeLastAssessed == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "timeLastAssessed");
            }
            this.timeLastAssessed = timeLastAssessed;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder triggeredBy(String triggeredBy) {
            if (triggeredBy == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "triggeredBy");
            }
            this.triggeredBy = triggeredBy;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentResult", "type");
            }
            this.type = type;
            return this;
        }
        public GetSecurityAssessmentResult build() {
            final var _resultValue = new GetSecurityAssessmentResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.ignoredAssessmentIds = ignoredAssessmentIds;
            _resultValue.ignoredTargets = ignoredTargets;
            _resultValue.isAssessmentScheduled = isAssessmentScheduled;
            _resultValue.isBaseline = isBaseline;
            _resultValue.isDeviatedFromBaseline = isDeviatedFromBaseline;
            _resultValue.lastComparedBaselineId = lastComparedBaselineId;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.link = link;
            _resultValue.schedule = schedule;
            _resultValue.scheduleSecurityAssessmentId = scheduleSecurityAssessmentId;
            _resultValue.securityAssessmentId = securityAssessmentId;
            _resultValue.state = state;
            _resultValue.statistics = statistics;
            _resultValue.systemTags = systemTags;
            _resultValue.targetId = targetId;
            _resultValue.targetIds = targetIds;
            _resultValue.targetVersion = targetVersion;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeLastAssessed = timeLastAssessed;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.triggeredBy = triggeredBy;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
