// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabasesFilter;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabasesTargetDatabase;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetTargetDatabasesResult {
    private @Nullable String accessLevel;
    private @Nullable String associatedResourceId;
    /**
     * @return The OCID of the compartment which contains the Data Safe target database.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return The database type.
     * 
     */
    private @Nullable String databaseType;
    /**
     * @return The display name of the target database in Data Safe.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetTargetDatabasesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The infrastructure type the database is running on.
     * 
     */
    private @Nullable String infrastructureType;
    /**
     * @return The current state of the target database in Data Safe.
     * 
     */
    private @Nullable String state;
    private @Nullable String targetDatabaseId;
    /**
     * @return The list of target_databases.
     * 
     */
    private List<GetTargetDatabasesTargetDatabase> targetDatabases;

    private GetTargetDatabasesResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    public Optional<String> associatedResourceId() {
        return Optional.ofNullable(this.associatedResourceId);
    }
    /**
     * @return The OCID of the compartment which contains the Data Safe target database.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return The database type.
     * 
     */
    public Optional<String> databaseType() {
        return Optional.ofNullable(this.databaseType);
    }
    /**
     * @return The display name of the target database in Data Safe.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetTargetDatabasesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The infrastructure type the database is running on.
     * 
     */
    public Optional<String> infrastructureType() {
        return Optional.ofNullable(this.infrastructureType);
    }
    /**
     * @return The current state of the target database in Data Safe.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> targetDatabaseId() {
        return Optional.ofNullable(this.targetDatabaseId);
    }
    /**
     * @return The list of target_databases.
     * 
     */
    public List<GetTargetDatabasesTargetDatabase> targetDatabases() {
        return this.targetDatabases;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabasesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private @Nullable String associatedResourceId;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String databaseType;
        private @Nullable String displayName;
        private @Nullable List<GetTargetDatabasesFilter> filters;
        private String id;
        private @Nullable String infrastructureType;
        private @Nullable String state;
        private @Nullable String targetDatabaseId;
        private List<GetTargetDatabasesTargetDatabase> targetDatabases;
        public Builder() {}
        public Builder(GetTargetDatabasesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.associatedResourceId = defaults.associatedResourceId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.databaseType = defaults.databaseType;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.infrastructureType = defaults.infrastructureType;
    	      this.state = defaults.state;
    	      this.targetDatabaseId = defaults.targetDatabaseId;
    	      this.targetDatabases = defaults.targetDatabases;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder associatedResourceId(@Nullable String associatedResourceId) {
            this.associatedResourceId = associatedResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder databaseType(@Nullable String databaseType) {
            this.databaseType = databaseType;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetTargetDatabasesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetTargetDatabasesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder infrastructureType(@Nullable String infrastructureType) {
            this.infrastructureType = infrastructureType;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder targetDatabaseId(@Nullable String targetDatabaseId) {
            this.targetDatabaseId = targetDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder targetDatabases(List<GetTargetDatabasesTargetDatabase> targetDatabases) {
            this.targetDatabases = Objects.requireNonNull(targetDatabases);
            return this;
        }
        public Builder targetDatabases(GetTargetDatabasesTargetDatabase... targetDatabases) {
            return targetDatabases(List.of(targetDatabases));
        }
        public GetTargetDatabasesResult build() {
            final var o = new GetTargetDatabasesResult();
            o.accessLevel = accessLevel;
            o.associatedResourceId = associatedResourceId;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.databaseType = databaseType;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.infrastructureType = infrastructureType;
            o.state = state;
            o.targetDatabaseId = targetDatabaseId;
            o.targetDatabases = targetDatabases;
            return o;
        }
    }
}