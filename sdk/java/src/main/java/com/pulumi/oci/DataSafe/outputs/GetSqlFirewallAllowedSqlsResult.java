// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallAllowedSqlsFilter;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSqlFirewallAllowedSqlsResult {
    private @Nullable String accessLevel;
    /**
     * @return The OCID of the compartment containing the SQL firewall allowed SQL.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    private @Nullable List<GetSqlFirewallAllowedSqlsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String scimQuery;
    /**
     * @return The list of sql_firewall_allowed_sql_collection.
     * 
     */
    private List<GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection> sqlFirewallAllowedSqlCollections;

    private GetSqlFirewallAllowedSqlsResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return The OCID of the compartment containing the SQL firewall allowed SQL.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    public List<GetSqlFirewallAllowedSqlsFilter> filters() {
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
    /**
     * @return The list of sql_firewall_allowed_sql_collection.
     * 
     */
    public List<GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection> sqlFirewallAllowedSqlCollections() {
        return this.sqlFirewallAllowedSqlCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlFirewallAllowedSqlsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable List<GetSqlFirewallAllowedSqlsFilter> filters;
        private String id;
        private @Nullable String scimQuery;
        private List<GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection> sqlFirewallAllowedSqlCollections;
        public Builder() {}
        public Builder(GetSqlFirewallAllowedSqlsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.scimQuery = defaults.scimQuery;
    	      this.sqlFirewallAllowedSqlCollections = defaults.sqlFirewallAllowedSqlCollections;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
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
        public Builder filters(@Nullable List<GetSqlFirewallAllowedSqlsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSqlFirewallAllowedSqlsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder scimQuery(@Nullable String scimQuery) {
            this.scimQuery = scimQuery;
            return this;
        }
        @CustomType.Setter
        public Builder sqlFirewallAllowedSqlCollections(List<GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection> sqlFirewallAllowedSqlCollections) {
            this.sqlFirewallAllowedSqlCollections = Objects.requireNonNull(sqlFirewallAllowedSqlCollections);
            return this;
        }
        public Builder sqlFirewallAllowedSqlCollections(GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection... sqlFirewallAllowedSqlCollections) {
            return sqlFirewallAllowedSqlCollections(List.of(sqlFirewallAllowedSqlCollections));
        }
        public GetSqlFirewallAllowedSqlsResult build() {
            final var o = new GetSqlFirewallAllowedSqlsResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.filters = filters;
            o.id = id;
            o.scimQuery = scimQuery;
            o.sqlFirewallAllowedSqlCollections = sqlFirewallAllowedSqlCollections;
            return o;
        }
    }
}