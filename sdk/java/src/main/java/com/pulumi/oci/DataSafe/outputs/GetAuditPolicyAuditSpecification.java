// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAuditPolicyAuditSpecification {
    /**
     * @return The category to which the audit policy belongs.
     * 
     */
    private String auditPolicyCategory;
    /**
     * @return Indicates the audit policy name. Refer to the [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827) for seeded audit policy names. For custom policies, refer to the user-defined policy name created in the target database.
     * 
     */
    private String auditPolicyName;
    /**
     * @return Indicates the names of corresponding database policy ( or policies) in the target database.
     * 
     */
    private List<String> databasePolicyNames;
    /**
     * @return Indicates whether the policy has been enabled, disabled or partially enabled in the target database. The status is PARTIALLY_ENABLED if any of the constituent database audit policies is not enabled.
     * 
     */
    private String enableStatus;
    /**
     * @return Indicates on whom the audit policy is enabled.
     * 
     */
    private String enabledEntities;
    /**
     * @return Indicates whether the policy is already created on the target database.
     * 
     */
    private Boolean isCreated;
    /**
     * @return Indicates whether the policy by default is enabled for all users with no flexibility to alter the enablement conditions.
     * 
     */
    private Boolean isEnabledForAllUsers;
    /**
     * @return Indicates whether the audit policy is one of the seeded policies provided by Oracle Data Safe.
     * 
     */
    private Boolean isSeededInDataSafe;
    /**
     * @return Indicates whether the audit policy is one of the predefined policies provided by Oracle Database.
     * 
     */
    private Boolean isSeededInTarget;
    /**
     * @return Indicates whether the audit policy is available for provisioning/ de-provisioning from Oracle Data Safe, or is only available for displaying the current provisioning status from the target.
     * 
     */
    private Boolean isViewOnly;
    /**
     * @return Provides information about the policy that has been only partially enabled.
     * 
     */
    private String partiallyEnabledMsg;

    private GetAuditPolicyAuditSpecification() {}
    /**
     * @return The category to which the audit policy belongs.
     * 
     */
    public String auditPolicyCategory() {
        return this.auditPolicyCategory;
    }
    /**
     * @return Indicates the audit policy name. Refer to the [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827) for seeded audit policy names. For custom policies, refer to the user-defined policy name created in the target database.
     * 
     */
    public String auditPolicyName() {
        return this.auditPolicyName;
    }
    /**
     * @return Indicates the names of corresponding database policy ( or policies) in the target database.
     * 
     */
    public List<String> databasePolicyNames() {
        return this.databasePolicyNames;
    }
    /**
     * @return Indicates whether the policy has been enabled, disabled or partially enabled in the target database. The status is PARTIALLY_ENABLED if any of the constituent database audit policies is not enabled.
     * 
     */
    public String enableStatus() {
        return this.enableStatus;
    }
    /**
     * @return Indicates on whom the audit policy is enabled.
     * 
     */
    public String enabledEntities() {
        return this.enabledEntities;
    }
    /**
     * @return Indicates whether the policy is already created on the target database.
     * 
     */
    public Boolean isCreated() {
        return this.isCreated;
    }
    /**
     * @return Indicates whether the policy by default is enabled for all users with no flexibility to alter the enablement conditions.
     * 
     */
    public Boolean isEnabledForAllUsers() {
        return this.isEnabledForAllUsers;
    }
    /**
     * @return Indicates whether the audit policy is one of the seeded policies provided by Oracle Data Safe.
     * 
     */
    public Boolean isSeededInDataSafe() {
        return this.isSeededInDataSafe;
    }
    /**
     * @return Indicates whether the audit policy is one of the predefined policies provided by Oracle Database.
     * 
     */
    public Boolean isSeededInTarget() {
        return this.isSeededInTarget;
    }
    /**
     * @return Indicates whether the audit policy is available for provisioning/ de-provisioning from Oracle Data Safe, or is only available for displaying the current provisioning status from the target.
     * 
     */
    public Boolean isViewOnly() {
        return this.isViewOnly;
    }
    /**
     * @return Provides information about the policy that has been only partially enabled.
     * 
     */
    public String partiallyEnabledMsg() {
        return this.partiallyEnabledMsg;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditPolicyAuditSpecification defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String auditPolicyCategory;
        private String auditPolicyName;
        private List<String> databasePolicyNames;
        private String enableStatus;
        private String enabledEntities;
        private Boolean isCreated;
        private Boolean isEnabledForAllUsers;
        private Boolean isSeededInDataSafe;
        private Boolean isSeededInTarget;
        private Boolean isViewOnly;
        private String partiallyEnabledMsg;
        public Builder() {}
        public Builder(GetAuditPolicyAuditSpecification defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.auditPolicyCategory = defaults.auditPolicyCategory;
    	      this.auditPolicyName = defaults.auditPolicyName;
    	      this.databasePolicyNames = defaults.databasePolicyNames;
    	      this.enableStatus = defaults.enableStatus;
    	      this.enabledEntities = defaults.enabledEntities;
    	      this.isCreated = defaults.isCreated;
    	      this.isEnabledForAllUsers = defaults.isEnabledForAllUsers;
    	      this.isSeededInDataSafe = defaults.isSeededInDataSafe;
    	      this.isSeededInTarget = defaults.isSeededInTarget;
    	      this.isViewOnly = defaults.isViewOnly;
    	      this.partiallyEnabledMsg = defaults.partiallyEnabledMsg;
        }

        @CustomType.Setter
        public Builder auditPolicyCategory(String auditPolicyCategory) {
            if (auditPolicyCategory == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "auditPolicyCategory");
            }
            this.auditPolicyCategory = auditPolicyCategory;
            return this;
        }
        @CustomType.Setter
        public Builder auditPolicyName(String auditPolicyName) {
            if (auditPolicyName == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "auditPolicyName");
            }
            this.auditPolicyName = auditPolicyName;
            return this;
        }
        @CustomType.Setter
        public Builder databasePolicyNames(List<String> databasePolicyNames) {
            if (databasePolicyNames == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "databasePolicyNames");
            }
            this.databasePolicyNames = databasePolicyNames;
            return this;
        }
        public Builder databasePolicyNames(String... databasePolicyNames) {
            return databasePolicyNames(List.of(databasePolicyNames));
        }
        @CustomType.Setter
        public Builder enableStatus(String enableStatus) {
            if (enableStatus == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "enableStatus");
            }
            this.enableStatus = enableStatus;
            return this;
        }
        @CustomType.Setter
        public Builder enabledEntities(String enabledEntities) {
            if (enabledEntities == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "enabledEntities");
            }
            this.enabledEntities = enabledEntities;
            return this;
        }
        @CustomType.Setter
        public Builder isCreated(Boolean isCreated) {
            if (isCreated == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "isCreated");
            }
            this.isCreated = isCreated;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabledForAllUsers(Boolean isEnabledForAllUsers) {
            if (isEnabledForAllUsers == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "isEnabledForAllUsers");
            }
            this.isEnabledForAllUsers = isEnabledForAllUsers;
            return this;
        }
        @CustomType.Setter
        public Builder isSeededInDataSafe(Boolean isSeededInDataSafe) {
            if (isSeededInDataSafe == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "isSeededInDataSafe");
            }
            this.isSeededInDataSafe = isSeededInDataSafe;
            return this;
        }
        @CustomType.Setter
        public Builder isSeededInTarget(Boolean isSeededInTarget) {
            if (isSeededInTarget == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "isSeededInTarget");
            }
            this.isSeededInTarget = isSeededInTarget;
            return this;
        }
        @CustomType.Setter
        public Builder isViewOnly(Boolean isViewOnly) {
            if (isViewOnly == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "isViewOnly");
            }
            this.isViewOnly = isViewOnly;
            return this;
        }
        @CustomType.Setter
        public Builder partiallyEnabledMsg(String partiallyEnabledMsg) {
            if (partiallyEnabledMsg == null) {
              throw new MissingRequiredPropertyException("GetAuditPolicyAuditSpecification", "partiallyEnabledMsg");
            }
            this.partiallyEnabledMsg = partiallyEnabledMsg;
            return this;
        }
        public GetAuditPolicyAuditSpecification build() {
            final var _resultValue = new GetAuditPolicyAuditSpecification();
            _resultValue.auditPolicyCategory = auditPolicyCategory;
            _resultValue.auditPolicyName = auditPolicyName;
            _resultValue.databasePolicyNames = databasePolicyNames;
            _resultValue.enableStatus = enableStatus;
            _resultValue.enabledEntities = enabledEntities;
            _resultValue.isCreated = isCreated;
            _resultValue.isEnabledForAllUsers = isEnabledForAllUsers;
            _resultValue.isSeededInDataSafe = isSeededInDataSafe;
            _resultValue.isSeededInTarget = isSeededInTarget;
            _resultValue.isViewOnly = isViewOnly;
            _resultValue.partiallyEnabledMsg = partiallyEnabledMsg;
            return _resultValue;
        }
    }
}
