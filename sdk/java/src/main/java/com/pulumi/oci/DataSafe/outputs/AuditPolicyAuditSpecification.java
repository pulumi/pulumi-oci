// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AuditPolicyAuditSpecification {
    /**
     * @return The category to which the audit policy belongs.
     * 
     */
    private @Nullable String auditPolicyCategory;
    /**
     * @return Indicates the audit policy name. Refer to the [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827) for seeded audit policy names. For custom policies, refer to the user-defined policy name created in the target database.
     * 
     */
    private @Nullable String auditPolicyName;
    /**
     * @return Indicates the names of corresponding database policy ( or policies) in the target database.
     * 
     */
    private @Nullable List<String> databasePolicyNames;
    /**
     * @return Indicates whether the policy has been enabled, disabled or partially enabled in the target database. The status is PARTIALLY_ENABLED if any of the constituent database audit policies is not enabled.
     * 
     */
    private @Nullable String enableStatus;
    /**
     * @return Indicates on whom the audit policy is enabled.
     * 
     */
    private @Nullable String enabledEntities;
    /**
     * @return Indicates whether the policy is already created on the target database.
     * 
     */
    private @Nullable Boolean isCreated;
    /**
     * @return Indicates whether the policy by default is enabled for all users with no flexibility to alter the enablement conditions.
     * 
     */
    private @Nullable Boolean isEnabledForAllUsers;
    /**
     * @return Indicates whether the audit policy is one of the seeded policies provided by Oracle Data Safe.
     * 
     */
    private @Nullable Boolean isSeededInDataSafe;
    /**
     * @return Indicates whether the audit policy is one of the predefined policies provided by Oracle Database.
     * 
     */
    private @Nullable Boolean isSeededInTarget;
    /**
     * @return Indicates whether the audit policy is available for provisioning/ de-provisioning from Oracle Data Safe, or is only available for displaying the current provisioning status from the target.
     * 
     */
    private @Nullable Boolean isViewOnly;
    /**
     * @return Provides information about the policy that has been only partially enabled.
     * 
     */
    private @Nullable String partiallyEnabledMsg;

    private AuditPolicyAuditSpecification() {}
    /**
     * @return The category to which the audit policy belongs.
     * 
     */
    public Optional<String> auditPolicyCategory() {
        return Optional.ofNullable(this.auditPolicyCategory);
    }
    /**
     * @return Indicates the audit policy name. Refer to the [documentation](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/audit-policies.html#GUID-361A9A9A-7C21-4F5A-8945-9B3A0C472827) for seeded audit policy names. For custom policies, refer to the user-defined policy name created in the target database.
     * 
     */
    public Optional<String> auditPolicyName() {
        return Optional.ofNullable(this.auditPolicyName);
    }
    /**
     * @return Indicates the names of corresponding database policy ( or policies) in the target database.
     * 
     */
    public List<String> databasePolicyNames() {
        return this.databasePolicyNames == null ? List.of() : this.databasePolicyNames;
    }
    /**
     * @return Indicates whether the policy has been enabled, disabled or partially enabled in the target database. The status is PARTIALLY_ENABLED if any of the constituent database audit policies is not enabled.
     * 
     */
    public Optional<String> enableStatus() {
        return Optional.ofNullable(this.enableStatus);
    }
    /**
     * @return Indicates on whom the audit policy is enabled.
     * 
     */
    public Optional<String> enabledEntities() {
        return Optional.ofNullable(this.enabledEntities);
    }
    /**
     * @return Indicates whether the policy is already created on the target database.
     * 
     */
    public Optional<Boolean> isCreated() {
        return Optional.ofNullable(this.isCreated);
    }
    /**
     * @return Indicates whether the policy by default is enabled for all users with no flexibility to alter the enablement conditions.
     * 
     */
    public Optional<Boolean> isEnabledForAllUsers() {
        return Optional.ofNullable(this.isEnabledForAllUsers);
    }
    /**
     * @return Indicates whether the audit policy is one of the seeded policies provided by Oracle Data Safe.
     * 
     */
    public Optional<Boolean> isSeededInDataSafe() {
        return Optional.ofNullable(this.isSeededInDataSafe);
    }
    /**
     * @return Indicates whether the audit policy is one of the predefined policies provided by Oracle Database.
     * 
     */
    public Optional<Boolean> isSeededInTarget() {
        return Optional.ofNullable(this.isSeededInTarget);
    }
    /**
     * @return Indicates whether the audit policy is available for provisioning/ de-provisioning from Oracle Data Safe, or is only available for displaying the current provisioning status from the target.
     * 
     */
    public Optional<Boolean> isViewOnly() {
        return Optional.ofNullable(this.isViewOnly);
    }
    /**
     * @return Provides information about the policy that has been only partially enabled.
     * 
     */
    public Optional<String> partiallyEnabledMsg() {
        return Optional.ofNullable(this.partiallyEnabledMsg);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AuditPolicyAuditSpecification defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String auditPolicyCategory;
        private @Nullable String auditPolicyName;
        private @Nullable List<String> databasePolicyNames;
        private @Nullable String enableStatus;
        private @Nullable String enabledEntities;
        private @Nullable Boolean isCreated;
        private @Nullable Boolean isEnabledForAllUsers;
        private @Nullable Boolean isSeededInDataSafe;
        private @Nullable Boolean isSeededInTarget;
        private @Nullable Boolean isViewOnly;
        private @Nullable String partiallyEnabledMsg;
        public Builder() {}
        public Builder(AuditPolicyAuditSpecification defaults) {
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
        public Builder auditPolicyCategory(@Nullable String auditPolicyCategory) {
            this.auditPolicyCategory = auditPolicyCategory;
            return this;
        }
        @CustomType.Setter
        public Builder auditPolicyName(@Nullable String auditPolicyName) {
            this.auditPolicyName = auditPolicyName;
            return this;
        }
        @CustomType.Setter
        public Builder databasePolicyNames(@Nullable List<String> databasePolicyNames) {
            this.databasePolicyNames = databasePolicyNames;
            return this;
        }
        public Builder databasePolicyNames(String... databasePolicyNames) {
            return databasePolicyNames(List.of(databasePolicyNames));
        }
        @CustomType.Setter
        public Builder enableStatus(@Nullable String enableStatus) {
            this.enableStatus = enableStatus;
            return this;
        }
        @CustomType.Setter
        public Builder enabledEntities(@Nullable String enabledEntities) {
            this.enabledEntities = enabledEntities;
            return this;
        }
        @CustomType.Setter
        public Builder isCreated(@Nullable Boolean isCreated) {
            this.isCreated = isCreated;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabledForAllUsers(@Nullable Boolean isEnabledForAllUsers) {
            this.isEnabledForAllUsers = isEnabledForAllUsers;
            return this;
        }
        @CustomType.Setter
        public Builder isSeededInDataSafe(@Nullable Boolean isSeededInDataSafe) {
            this.isSeededInDataSafe = isSeededInDataSafe;
            return this;
        }
        @CustomType.Setter
        public Builder isSeededInTarget(@Nullable Boolean isSeededInTarget) {
            this.isSeededInTarget = isSeededInTarget;
            return this;
        }
        @CustomType.Setter
        public Builder isViewOnly(@Nullable Boolean isViewOnly) {
            this.isViewOnly = isViewOnly;
            return this;
        }
        @CustomType.Setter
        public Builder partiallyEnabledMsg(@Nullable String partiallyEnabledMsg) {
            this.partiallyEnabledMsg = partiallyEnabledMsg;
            return this;
        }
        public AuditPolicyAuditSpecification build() {
            final var o = new AuditPolicyAuditSpecification();
            o.auditPolicyCategory = auditPolicyCategory;
            o.auditPolicyName = auditPolicyName;
            o.databasePolicyNames = databasePolicyNames;
            o.enableStatus = enableStatus;
            o.enabledEntities = enabledEntities;
            o.isCreated = isCreated;
            o.isEnabledForAllUsers = isEnabledForAllUsers;
            o.isSeededInDataSafe = isSeededInDataSafe;
            o.isSeededInTarget = isSeededInTarget;
            o.isViewOnly = isViewOnly;
            o.partiallyEnabledMsg = partiallyEnabledMsg;
            return o;
        }
    }
}