// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetSecurityPolicyReportDatabaseViewAccessEntriesDatabaseViewAccessEntryCollection;
import com.pulumi.oci.DataSafe.outputs.GetSecurityPolicyReportDatabaseViewAccessEntriesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSecurityPolicyReportDatabaseViewAccessEntriesResult {
    /**
     * @return The list of database_view_access_entry_collection.
     * 
     */
    private List<GetSecurityPolicyReportDatabaseViewAccessEntriesDatabaseViewAccessEntryCollection> databaseViewAccessEntryCollections;
    private @Nullable List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String scimQuery;
    private String securityPolicyReportId;
    /**
     * @return The OCID of the of the  target database.
     * 
     */
    private @Nullable String targetId;

    private GetSecurityPolicyReportDatabaseViewAccessEntriesResult() {}
    /**
     * @return The list of database_view_access_entry_collection.
     * 
     */
    public List<GetSecurityPolicyReportDatabaseViewAccessEntriesDatabaseViewAccessEntryCollection> databaseViewAccessEntryCollections() {
        return this.databaseViewAccessEntryCollections;
    }
    public List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> scimQuery() {
        return Optional.ofNullable(this.scimQuery);
    }
    public String securityPolicyReportId() {
        return this.securityPolicyReportId;
    }
    /**
     * @return The OCID of the of the  target database.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityPolicyReportDatabaseViewAccessEntriesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSecurityPolicyReportDatabaseViewAccessEntriesDatabaseViewAccessEntryCollection> databaseViewAccessEntryCollections;
        private @Nullable List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilter> filters;
        private String id;
        private @Nullable String scimQuery;
        private String securityPolicyReportId;
        private @Nullable String targetId;
        public Builder() {}
        public Builder(GetSecurityPolicyReportDatabaseViewAccessEntriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseViewAccessEntryCollections = defaults.databaseViewAccessEntryCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.scimQuery = defaults.scimQuery;
    	      this.securityPolicyReportId = defaults.securityPolicyReportId;
    	      this.targetId = defaults.targetId;
        }

        @CustomType.Setter
        public Builder databaseViewAccessEntryCollections(List<GetSecurityPolicyReportDatabaseViewAccessEntriesDatabaseViewAccessEntryCollection> databaseViewAccessEntryCollections) {
            if (databaseViewAccessEntryCollections == null) {
              throw new MissingRequiredPropertyException("GetSecurityPolicyReportDatabaseViewAccessEntriesResult", "databaseViewAccessEntryCollections");
            }
            this.databaseViewAccessEntryCollections = databaseViewAccessEntryCollections;
            return this;
        }
        public Builder databaseViewAccessEntryCollections(GetSecurityPolicyReportDatabaseViewAccessEntriesDatabaseViewAccessEntryCollection... databaseViewAccessEntryCollections) {
            return databaseViewAccessEntryCollections(List.of(databaseViewAccessEntryCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSecurityPolicyReportDatabaseViewAccessEntriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSecurityPolicyReportDatabaseViewAccessEntriesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder scimQuery(@Nullable String scimQuery) {

            this.scimQuery = scimQuery;
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyReportId(String securityPolicyReportId) {
            if (securityPolicyReportId == null) {
              throw new MissingRequiredPropertyException("GetSecurityPolicyReportDatabaseViewAccessEntriesResult", "securityPolicyReportId");
            }
            this.securityPolicyReportId = securityPolicyReportId;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(@Nullable String targetId) {

            this.targetId = targetId;
            return this;
        }
        public GetSecurityPolicyReportDatabaseViewAccessEntriesResult build() {
            final var _resultValue = new GetSecurityPolicyReportDatabaseViewAccessEntriesResult();
            _resultValue.databaseViewAccessEntryCollections = databaseViewAccessEntryCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.scimQuery = scimQuery;
            _resultValue.securityPolicyReportId = securityPolicyReportId;
            _resultValue.targetId = targetId;
            return _resultValue;
        }
    }
}
