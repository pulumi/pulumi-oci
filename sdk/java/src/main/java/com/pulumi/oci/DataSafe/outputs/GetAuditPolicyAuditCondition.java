// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetAuditPolicyAuditConditionEnableCondition;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAuditPolicyAuditCondition {
    /**
     * @return Indicates the audit policy name. Refer to the [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827) for seeded audit policy names. For custom policies, refer to the user-defined policy name created in the target database.
     * 
     */
    private String auditPolicyName;
    /**
     * @return Indicates the users/roles in the target database for which the audit policy is enforced, and the success/failure event condition to generate the audit event..
     * 
     */
    private List<GetAuditPolicyAuditConditionEnableCondition> enableConditions;
    /**
     * @return Indicates whether the Data Safe user activity on the target database will be audited by the policy.
     * 
     */
    private Boolean isDataSafeServiceAccountAudited;
    /**
     * @return Indicates whether the privileged user list is managed by Data Safe.
     * 
     */
    private Boolean isPrivUsersManagedByDataSafe;

    private GetAuditPolicyAuditCondition() {}
    /**
     * @return Indicates the audit policy name. Refer to the [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827) for seeded audit policy names. For custom policies, refer to the user-defined policy name created in the target database.
     * 
     */
    public String auditPolicyName() {
        return this.auditPolicyName;
    }
    /**
     * @return Indicates the users/roles in the target database for which the audit policy is enforced, and the success/failure event condition to generate the audit event..
     * 
     */
    public List<GetAuditPolicyAuditConditionEnableCondition> enableConditions() {
        return this.enableConditions;
    }
    /**
     * @return Indicates whether the Data Safe user activity on the target database will be audited by the policy.
     * 
     */
    public Boolean isDataSafeServiceAccountAudited() {
        return this.isDataSafeServiceAccountAudited;
    }
    /**
     * @return Indicates whether the privileged user list is managed by Data Safe.
     * 
     */
    public Boolean isPrivUsersManagedByDataSafe() {
        return this.isPrivUsersManagedByDataSafe;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditPolicyAuditCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String auditPolicyName;
        private List<GetAuditPolicyAuditConditionEnableCondition> enableConditions;
        private Boolean isDataSafeServiceAccountAudited;
        private Boolean isPrivUsersManagedByDataSafe;
        public Builder() {}
        public Builder(GetAuditPolicyAuditCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.auditPolicyName = defaults.auditPolicyName;
    	      this.enableConditions = defaults.enableConditions;
    	      this.isDataSafeServiceAccountAudited = defaults.isDataSafeServiceAccountAudited;
    	      this.isPrivUsersManagedByDataSafe = defaults.isPrivUsersManagedByDataSafe;
        }

        @CustomType.Setter
        public Builder auditPolicyName(String auditPolicyName) {
            this.auditPolicyName = Objects.requireNonNull(auditPolicyName);
            return this;
        }
        @CustomType.Setter
        public Builder enableConditions(List<GetAuditPolicyAuditConditionEnableCondition> enableConditions) {
            this.enableConditions = Objects.requireNonNull(enableConditions);
            return this;
        }
        public Builder enableConditions(GetAuditPolicyAuditConditionEnableCondition... enableConditions) {
            return enableConditions(List.of(enableConditions));
        }
        @CustomType.Setter
        public Builder isDataSafeServiceAccountAudited(Boolean isDataSafeServiceAccountAudited) {
            this.isDataSafeServiceAccountAudited = Objects.requireNonNull(isDataSafeServiceAccountAudited);
            return this;
        }
        @CustomType.Setter
        public Builder isPrivUsersManagedByDataSafe(Boolean isPrivUsersManagedByDataSafe) {
            this.isPrivUsersManagedByDataSafe = Objects.requireNonNull(isPrivUsersManagedByDataSafe);
            return this;
        }
        public GetAuditPolicyAuditCondition build() {
            final var o = new GetAuditPolicyAuditCondition();
            o.auditPolicyName = auditPolicyName;
            o.enableConditions = enableConditions;
            o.isDataSafeServiceAccountAudited = isDataSafeServiceAccountAudited;
            o.isPrivUsersManagedByDataSafe = isPrivUsersManagedByDataSafe;
            return o;
        }
    }
}