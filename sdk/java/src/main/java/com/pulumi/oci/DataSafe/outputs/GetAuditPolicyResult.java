// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetAuditPolicyAuditCondition;
import com.pulumi.oci.DataSafe.outputs.GetAuditPolicyAuditSpecification;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAuditPolicyResult {
    /**
     * @return Lists the audit policy provisioning conditions for the target database.
     * 
     */
    private List<GetAuditPolicyAuditCondition> auditConditions;
    private String auditPolicyId;
    /**
     * @return Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
     * 
     */
    private List<GetAuditPolicyAuditSpecification> auditSpecifications;
    /**
     * @return The OCID of the compartment containing the audit policy.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Description of the audit policy.
     * 
     */
    private String description;
    /**
     * @return The display name of the audit policy.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the audit policy.
     * 
     */
    private String id;
    /**
     * @return Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
     * 
     */
    private Boolean isDataSafeServiceAccountExcluded;
    /**
     * @return Details about the current state of the audit policy in Data Safe.
     * 
     */
    private String lifecycleDetails;
    private Integer provisionTrigger;
    private Integer retrieveFromTargetTrigger;
    /**
     * @return The current state of the audit policy.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The OCID of the target for which the audit policy is created.
     * 
     */
    private String targetId;
    /**
     * @return The time the the audit policy was created, in the format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
     * 
     */
    private String timeLastProvisioned;
    /**
     * @return The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
     * 
     */
    private String timeLastRetrieved;
    /**
     * @return The last date and time the audit policy was updated, in the format defined by RFC3339.
     * 
     */
    private String timeUpdated;

    private GetAuditPolicyResult() {}
    /**
     * @return Lists the audit policy provisioning conditions for the target database.
     * 
     */
    public List<GetAuditPolicyAuditCondition> auditConditions() {
        return this.auditConditions;
    }
    public String auditPolicyId() {
        return this.auditPolicyId;
    }
    /**
     * @return Represents all available audit policy specifications relevant for the target database. For more details on available audit polcies, refer to [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827).
     * 
     */
    public List<GetAuditPolicyAuditSpecification> auditSpecifications() {
        return this.auditSpecifications;
    }
    /**
     * @return The OCID of the compartment containing the audit policy.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description of the audit policy.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The display name of the audit policy.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the audit policy.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Option provided to users at the target to indicate whether the Data Safe service account has to be excluded while provisioning the audit policies.
     * 
     */
    public Boolean isDataSafeServiceAccountExcluded() {
        return this.isDataSafeServiceAccountExcluded;
    }
    /**
     * @return Details about the current state of the audit policy in Data Safe.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public Integer provisionTrigger() {
        return this.provisionTrigger;
    }
    public Integer retrieveFromTargetTrigger() {
        return this.retrieveFromTargetTrigger;
    }
    /**
     * @return The current state of the audit policy.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The OCID of the target for which the audit policy is created.
     * 
     */
    public String targetId() {
        return this.targetId;
    }
    /**
     * @return The time the the audit policy was created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Indicates the last provisioning time of audit policies on the target, in the format defined by RFC3339.
     * 
     */
    public String timeLastProvisioned() {
        return this.timeLastProvisioned;
    }
    /**
     * @return The time when the audit policies was last retrieved from this target, in the format defined by RFC3339.
     * 
     */
    public String timeLastRetrieved() {
        return this.timeLastRetrieved;
    }
    /**
     * @return The last date and time the audit policy was updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditPolicyResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAuditPolicyAuditCondition> auditConditions;
        private String auditPolicyId;
        private List<GetAuditPolicyAuditSpecification> auditSpecifications;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isDataSafeServiceAccountExcluded;
        private String lifecycleDetails;
        private Integer provisionTrigger;
        private Integer retrieveFromTargetTrigger;
        private String state;
        private Map<String,Object> systemTags;
        private String targetId;
        private String timeCreated;
        private String timeLastProvisioned;
        private String timeLastRetrieved;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetAuditPolicyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.auditConditions = defaults.auditConditions;
    	      this.auditPolicyId = defaults.auditPolicyId;
    	      this.auditSpecifications = defaults.auditSpecifications;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isDataSafeServiceAccountExcluded = defaults.isDataSafeServiceAccountExcluded;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.provisionTrigger = defaults.provisionTrigger;
    	      this.retrieveFromTargetTrigger = defaults.retrieveFromTargetTrigger;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targetId = defaults.targetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastProvisioned = defaults.timeLastProvisioned;
    	      this.timeLastRetrieved = defaults.timeLastRetrieved;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder auditConditions(List<GetAuditPolicyAuditCondition> auditConditions) {
            this.auditConditions = Objects.requireNonNull(auditConditions);
            return this;
        }
        public Builder auditConditions(GetAuditPolicyAuditCondition... auditConditions) {
            return auditConditions(List.of(auditConditions));
        }
        @CustomType.Setter
        public Builder auditPolicyId(String auditPolicyId) {
            this.auditPolicyId = Objects.requireNonNull(auditPolicyId);
            return this;
        }
        @CustomType.Setter
        public Builder auditSpecifications(List<GetAuditPolicyAuditSpecification> auditSpecifications) {
            this.auditSpecifications = Objects.requireNonNull(auditSpecifications);
            return this;
        }
        public Builder auditSpecifications(GetAuditPolicyAuditSpecification... auditSpecifications) {
            return auditSpecifications(List.of(auditSpecifications));
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
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
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
        public Builder isDataSafeServiceAccountExcluded(Boolean isDataSafeServiceAccountExcluded) {
            this.isDataSafeServiceAccountExcluded = Objects.requireNonNull(isDataSafeServiceAccountExcluded);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder provisionTrigger(Integer provisionTrigger) {
            this.provisionTrigger = Objects.requireNonNull(provisionTrigger);
            return this;
        }
        @CustomType.Setter
        public Builder retrieveFromTargetTrigger(Integer retrieveFromTargetTrigger) {
            this.retrieveFromTargetTrigger = Objects.requireNonNull(retrieveFromTargetTrigger);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            this.targetId = Objects.requireNonNull(targetId);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeLastProvisioned(String timeLastProvisioned) {
            this.timeLastProvisioned = Objects.requireNonNull(timeLastProvisioned);
            return this;
        }
        @CustomType.Setter
        public Builder timeLastRetrieved(String timeLastRetrieved) {
            this.timeLastRetrieved = Objects.requireNonNull(timeLastRetrieved);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetAuditPolicyResult build() {
            final var o = new GetAuditPolicyResult();
            o.auditConditions = auditConditions;
            o.auditPolicyId = auditPolicyId;
            o.auditSpecifications = auditSpecifications;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isDataSafeServiceAccountExcluded = isDataSafeServiceAccountExcluded;
            o.lifecycleDetails = lifecycleDetails;
            o.provisionTrigger = provisionTrigger;
            o.retrieveFromTargetTrigger = retrieveFromTargetTrigger;
            o.state = state;
            o.systemTags = systemTags;
            o.targetId = targetId;
            o.timeCreated = timeCreated;
            o.timeLastProvisioned = timeLastProvisioned;
            o.timeLastRetrieved = timeLastRetrieved;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}