// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetDbHomePatchHistoryEntriesFilter;
import com.pulumi.oci.Database.outputs.GetDbHomePatchHistoryEntriesPatchHistoryEntry;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetDbHomePatchHistoryEntriesResult {
    private final String dbHomeId;
    private final @Nullable List<GetDbHomePatchHistoryEntriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of patch_history_entries.
     * 
     */
    private final List<GetDbHomePatchHistoryEntriesPatchHistoryEntry> patchHistoryEntries;

    @CustomType.Constructor
    private GetDbHomePatchHistoryEntriesResult(
        @CustomType.Parameter("dbHomeId") String dbHomeId,
        @CustomType.Parameter("filters") @Nullable List<GetDbHomePatchHistoryEntriesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("patchHistoryEntries") List<GetDbHomePatchHistoryEntriesPatchHistoryEntry> patchHistoryEntries) {
        this.dbHomeId = dbHomeId;
        this.filters = filters;
        this.id = id;
        this.patchHistoryEntries = patchHistoryEntries;
    }

    public String dbHomeId() {
        return this.dbHomeId;
    }
    public List<GetDbHomePatchHistoryEntriesFilter> filters() {
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
     * @return The list of patch_history_entries.
     * 
     */
    public List<GetDbHomePatchHistoryEntriesPatchHistoryEntry> patchHistoryEntries() {
        return this.patchHistoryEntries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbHomePatchHistoryEntriesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String dbHomeId;
        private @Nullable List<GetDbHomePatchHistoryEntriesFilter> filters;
        private String id;
        private List<GetDbHomePatchHistoryEntriesPatchHistoryEntry> patchHistoryEntries;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDbHomePatchHistoryEntriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbHomeId = defaults.dbHomeId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.patchHistoryEntries = defaults.patchHistoryEntries;
        }

        public Builder dbHomeId(String dbHomeId) {
            this.dbHomeId = Objects.requireNonNull(dbHomeId);
            return this;
        }
        public Builder filters(@Nullable List<GetDbHomePatchHistoryEntriesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDbHomePatchHistoryEntriesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder patchHistoryEntries(List<GetDbHomePatchHistoryEntriesPatchHistoryEntry> patchHistoryEntries) {
            this.patchHistoryEntries = Objects.requireNonNull(patchHistoryEntries);
            return this;
        }
        public Builder patchHistoryEntries(GetDbHomePatchHistoryEntriesPatchHistoryEntry... patchHistoryEntries) {
            return patchHistoryEntries(List.of(patchHistoryEntries));
        }        public GetDbHomePatchHistoryEntriesResult build() {
            return new GetDbHomePatchHistoryEntriesResult(dbHomeId, filters, id, patchHistoryEntries);
        }
    }
}
