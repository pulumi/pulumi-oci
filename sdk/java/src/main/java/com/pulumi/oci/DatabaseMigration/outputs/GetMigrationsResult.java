// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsFilter;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetMigrationsResult {
    /**
     * @return OCID of the compartment where the secret containing the credentials will be created.
     * 
     */
    private final String compartmentId;
    /**
     * @return Migration Display Name
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetMigrationsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return Additional status related to the execution and current state of the Migration.
     * 
     */
    private final @Nullable String lifecycleDetails;
    /**
     * @return The list of migration_collection.
     * 
     */
    private final List<GetMigrationsMigrationCollection> migrationCollections;
    /**
     * @return The current state of the Migration resource.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetMigrationsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetMigrationsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("lifecycleDetails") @Nullable String lifecycleDetails,
        @CustomType.Parameter("migrationCollections") List<GetMigrationsMigrationCollection> migrationCollections,
        @CustomType.Parameter("state") @Nullable String state) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.lifecycleDetails = lifecycleDetails;
        this.migrationCollections = migrationCollections;
        this.state = state;
    }

    /**
     * @return OCID of the compartment where the secret containing the credentials will be created.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Migration Display Name
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetMigrationsFilter> filters() {
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
     * @return Additional status related to the execution and current state of the Migration.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return The list of migration_collection.
     * 
     */
    public List<GetMigrationsMigrationCollection> migrationCollections() {
        return this.migrationCollections;
    }
    /**
     * @return The current state of the Migration resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetMigrationsFilter> filters;
        private String id;
        private @Nullable String lifecycleDetails;
        private List<GetMigrationsMigrationCollection> migrationCollections;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.migrationCollections = defaults.migrationCollections;
    	      this.state = defaults.state;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetMigrationsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetMigrationsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        public Builder migrationCollections(List<GetMigrationsMigrationCollection> migrationCollections) {
            this.migrationCollections = Objects.requireNonNull(migrationCollections);
            return this;
        }
        public Builder migrationCollections(GetMigrationsMigrationCollection... migrationCollections) {
            return migrationCollections(List.of(migrationCollections));
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetMigrationsResult build() {
            return new GetMigrationsResult(compartmentId, displayName, filters, id, lifecycleDetails, migrationCollections, state);
        }
    }
}
