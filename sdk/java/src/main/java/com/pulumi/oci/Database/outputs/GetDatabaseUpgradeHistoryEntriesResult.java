// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry;
import com.pulumi.oci.Database.outputs.GetDatabaseUpgradeHistoryEntriesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDatabaseUpgradeHistoryEntriesResult {
    private final String databaseId;
    /**
     * @return The list of database_upgrade_history_entries.
     * 
     */
    private final List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries;
    private final @Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
     * 
     */
    private final @Nullable String state;
    private final @Nullable String upgradeAction;

    @CustomType.Constructor
    private GetDatabaseUpgradeHistoryEntriesResult(
        @CustomType.Parameter("databaseId") String databaseId,
        @CustomType.Parameter("databaseUpgradeHistoryEntries") List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries,
        @CustomType.Parameter("filters") @Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("upgradeAction") @Nullable String upgradeAction) {
        this.databaseId = databaseId;
        this.databaseUpgradeHistoryEntries = databaseUpgradeHistoryEntries;
        this.filters = filters;
        this.id = id;
        this.state = state;
        this.upgradeAction = upgradeAction;
    }

    public String databaseId() {
        return this.databaseId;
    }
    /**
     * @return The list of database_upgrade_history_entries.
     * 
     */
    public List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries() {
        return this.databaseUpgradeHistoryEntries;
    }
    public List<GetDatabaseUpgradeHistoryEntriesFilter> filters() {
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
     * @return Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> upgradeAction() {
        return Optional.ofNullable(this.upgradeAction);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseUpgradeHistoryEntriesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String databaseId;
        private List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries;
        private @Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String upgradeAction;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDatabaseUpgradeHistoryEntriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseId = defaults.databaseId;
    	      this.databaseUpgradeHistoryEntries = defaults.databaseUpgradeHistoryEntries;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.upgradeAction = defaults.upgradeAction;
        }

        public Builder databaseId(String databaseId) {
            this.databaseId = Objects.requireNonNull(databaseId);
            return this;
        }
        public Builder databaseUpgradeHistoryEntries(List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries) {
            this.databaseUpgradeHistoryEntries = Objects.requireNonNull(databaseUpgradeHistoryEntries);
            return this;
        }
        public Builder databaseUpgradeHistoryEntries(GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry... databaseUpgradeHistoryEntries) {
            return databaseUpgradeHistoryEntries(List.of(databaseUpgradeHistoryEntries));
        }
        public Builder filters(@Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDatabaseUpgradeHistoryEntriesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder upgradeAction(@Nullable String upgradeAction) {
            this.upgradeAction = upgradeAction;
            return this;
        }        public GetDatabaseUpgradeHistoryEntriesResult build() {
            return new GetDatabaseUpgradeHistoryEntriesResult(databaseId, databaseUpgradeHistoryEntries, filters, id, state, upgradeAction);
        }
    }
}
