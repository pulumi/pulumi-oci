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
    private String databaseId;
    /**
     * @return The list of database_upgrade_history_entries.
     * 
     */
    private List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries;
    private @Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
     * 
     */
    private @Nullable String state;
    private @Nullable String upgradeAction;

    private GetDatabaseUpgradeHistoryEntriesResult() {}
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
    @CustomType.Builder
    public static final class Builder {
        private String databaseId;
        private List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries;
        private @Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String upgradeAction;
        public Builder() {}
        public Builder(GetDatabaseUpgradeHistoryEntriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseId = defaults.databaseId;
    	      this.databaseUpgradeHistoryEntries = defaults.databaseUpgradeHistoryEntries;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.upgradeAction = defaults.upgradeAction;
        }

        @CustomType.Setter
        public Builder databaseId(String databaseId) {
            this.databaseId = Objects.requireNonNull(databaseId);
            return this;
        }
        @CustomType.Setter
        public Builder databaseUpgradeHistoryEntries(List<GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry> databaseUpgradeHistoryEntries) {
            this.databaseUpgradeHistoryEntries = Objects.requireNonNull(databaseUpgradeHistoryEntries);
            return this;
        }
        public Builder databaseUpgradeHistoryEntries(GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry... databaseUpgradeHistoryEntries) {
            return databaseUpgradeHistoryEntries(List.of(databaseUpgradeHistoryEntries));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDatabaseUpgradeHistoryEntriesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDatabaseUpgradeHistoryEntriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder upgradeAction(@Nullable String upgradeAction) {
            this.upgradeAction = upgradeAction;
            return this;
        }
        public GetDatabaseUpgradeHistoryEntriesResult build() {
            final var o = new GetDatabaseUpgradeHistoryEntriesResult();
            o.databaseId = databaseId;
            o.databaseUpgradeHistoryEntries = databaseUpgradeHistoryEntries;
            o.filters = filters;
            o.id = id;
            o.state = state;
            o.upgradeAction = upgradeAction;
            return o;
        }
    }
}