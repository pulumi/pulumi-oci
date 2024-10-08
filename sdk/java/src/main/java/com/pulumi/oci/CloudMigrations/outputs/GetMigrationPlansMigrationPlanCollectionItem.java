// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStat;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlansMigrationPlanCollectionItemStrategy;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlansMigrationPlanCollectionItemTargetEnvironment;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetMigrationPlansMigrationPlanCollectionItem {
    /**
     * @return Limits of the resources that are needed for migration. Example: {&#34;BlockVolume&#34;: 2, &#34;VCN&#34;: 1}
     * 
     */
    private Map<String,String> calculatedLimits;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only resources that match the entire given display name.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The unique Oracle ID (OCID) that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Unique migration identifier
     * 
     */
    private String migrationId;
    /**
     * @return Status of the migration plan.
     * 
     */
    private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStat> migrationPlanStats;
    /**
     * @return OCID of the referenced ORM job.
     * 
     */
    private String referenceToRmsStack;
    /**
     * @return Source migraiton plan ID to be cloned.
     * 
     */
    private String sourceMigrationPlanId;
    /**
     * @return The current state of the migration plan.
     * 
     */
    private String state;
    /**
     * @return List of strategies for the resources to be migrated.
     * 
     */
    private List<GetMigrationPlansMigrationPlanCollectionItemStrategy> strategies;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return List of target environments.
     * 
     */
    private List<GetMigrationPlansMigrationPlanCollectionItemTargetEnvironment> targetEnvironments;
    /**
     * @return The time when the migration plan was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetMigrationPlansMigrationPlanCollectionItem() {}
    /**
     * @return Limits of the resources that are needed for migration. Example: {&#34;BlockVolume&#34;: 2, &#34;VCN&#34;: 1}
     * 
     */
    public Map<String,String> calculatedLimits() {
        return this.calculatedLimits;
    }
    /**
     * @return The ID of the compartment in which to list resources.
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
     * @return A filter to return only resources that match the entire given display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The unique Oracle ID (OCID) that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Unique migration identifier
     * 
     */
    public String migrationId() {
        return this.migrationId;
    }
    /**
     * @return Status of the migration plan.
     * 
     */
    public List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStat> migrationPlanStats() {
        return this.migrationPlanStats;
    }
    /**
     * @return OCID of the referenced ORM job.
     * 
     */
    public String referenceToRmsStack() {
        return this.referenceToRmsStack;
    }
    /**
     * @return Source migraiton plan ID to be cloned.
     * 
     */
    public String sourceMigrationPlanId() {
        return this.sourceMigrationPlanId;
    }
    /**
     * @return The current state of the migration plan.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return List of strategies for the resources to be migrated.
     * 
     */
    public List<GetMigrationPlansMigrationPlanCollectionItemStrategy> strategies() {
        return this.strategies;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return List of target environments.
     * 
     */
    public List<GetMigrationPlansMigrationPlanCollectionItemTargetEnvironment> targetEnvironments() {
        return this.targetEnvironments;
    }
    /**
     * @return The time when the migration plan was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationPlansMigrationPlanCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,String> calculatedLimits;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String migrationId;
        private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStat> migrationPlanStats;
        private String referenceToRmsStack;
        private String sourceMigrationPlanId;
        private String state;
        private List<GetMigrationPlansMigrationPlanCollectionItemStrategy> strategies;
        private Map<String,String> systemTags;
        private List<GetMigrationPlansMigrationPlanCollectionItemTargetEnvironment> targetEnvironments;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetMigrationPlansMigrationPlanCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.calculatedLimits = defaults.calculatedLimits;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.migrationId = defaults.migrationId;
    	      this.migrationPlanStats = defaults.migrationPlanStats;
    	      this.referenceToRmsStack = defaults.referenceToRmsStack;
    	      this.sourceMigrationPlanId = defaults.sourceMigrationPlanId;
    	      this.state = defaults.state;
    	      this.strategies = defaults.strategies;
    	      this.systemTags = defaults.systemTags;
    	      this.targetEnvironments = defaults.targetEnvironments;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder calculatedLimits(Map<String,String> calculatedLimits) {
            if (calculatedLimits == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "calculatedLimits");
            }
            this.calculatedLimits = calculatedLimits;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder migrationId(String migrationId) {
            if (migrationId == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "migrationId");
            }
            this.migrationId = migrationId;
            return this;
        }
        @CustomType.Setter
        public Builder migrationPlanStats(List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStat> migrationPlanStats) {
            if (migrationPlanStats == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "migrationPlanStats");
            }
            this.migrationPlanStats = migrationPlanStats;
            return this;
        }
        public Builder migrationPlanStats(GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStat... migrationPlanStats) {
            return migrationPlanStats(List.of(migrationPlanStats));
        }
        @CustomType.Setter
        public Builder referenceToRmsStack(String referenceToRmsStack) {
            if (referenceToRmsStack == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "referenceToRmsStack");
            }
            this.referenceToRmsStack = referenceToRmsStack;
            return this;
        }
        @CustomType.Setter
        public Builder sourceMigrationPlanId(String sourceMigrationPlanId) {
            if (sourceMigrationPlanId == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "sourceMigrationPlanId");
            }
            this.sourceMigrationPlanId = sourceMigrationPlanId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder strategies(List<GetMigrationPlansMigrationPlanCollectionItemStrategy> strategies) {
            if (strategies == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "strategies");
            }
            this.strategies = strategies;
            return this;
        }
        public Builder strategies(GetMigrationPlansMigrationPlanCollectionItemStrategy... strategies) {
            return strategies(List.of(strategies));
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder targetEnvironments(List<GetMigrationPlansMigrationPlanCollectionItemTargetEnvironment> targetEnvironments) {
            if (targetEnvironments == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "targetEnvironments");
            }
            this.targetEnvironments = targetEnvironments;
            return this;
        }
        public Builder targetEnvironments(GetMigrationPlansMigrationPlanCollectionItemTargetEnvironment... targetEnvironments) {
            return targetEnvironments(List.of(targetEnvironments));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetMigrationPlansMigrationPlanCollectionItem build() {
            final var _resultValue = new GetMigrationPlansMigrationPlanCollectionItem();
            _resultValue.calculatedLimits = calculatedLimits;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.migrationId = migrationId;
            _resultValue.migrationPlanStats = migrationPlanStats;
            _resultValue.referenceToRmsStack = referenceToRmsStack;
            _resultValue.sourceMigrationPlanId = sourceMigrationPlanId;
            _resultValue.state = state;
            _resultValue.strategies = strategies;
            _resultValue.systemTags = systemTags;
            _resultValue.targetEnvironments = targetEnvironments;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
