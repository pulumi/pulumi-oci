// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseTableStatisticsFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseTableStatisticsTableStatisticsCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabaseTableStatisticsResult {
    private @Nullable List<GetManagedDatabaseTableStatisticsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedDatabaseId;
    /**
     * @return The list of table_statistics_collection.
     * 
     */
    private List<GetManagedDatabaseTableStatisticsTableStatisticsCollection> tableStatisticsCollections;

    private GetManagedDatabaseTableStatisticsResult() {}
    public List<GetManagedDatabaseTableStatisticsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * @return The list of table_statistics_collection.
     * 
     */
    public List<GetManagedDatabaseTableStatisticsTableStatisticsCollection> tableStatisticsCollections() {
        return this.tableStatisticsCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseTableStatisticsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetManagedDatabaseTableStatisticsFilter> filters;
        private String id;
        private String managedDatabaseId;
        private List<GetManagedDatabaseTableStatisticsTableStatisticsCollection> tableStatisticsCollections;
        public Builder() {}
        public Builder(GetManagedDatabaseTableStatisticsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.tableStatisticsCollections = defaults.tableStatisticsCollections;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedDatabaseTableStatisticsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedDatabaseTableStatisticsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder tableStatisticsCollections(List<GetManagedDatabaseTableStatisticsTableStatisticsCollection> tableStatisticsCollections) {
            this.tableStatisticsCollections = Objects.requireNonNull(tableStatisticsCollections);
            return this;
        }
        public Builder tableStatisticsCollections(GetManagedDatabaseTableStatisticsTableStatisticsCollection... tableStatisticsCollections) {
            return tableStatisticsCollections(List.of(tableStatisticsCollections));
        }
        public GetManagedDatabaseTableStatisticsResult build() {
            final var o = new GetManagedDatabaseTableStatisticsResult();
            o.filters = filters;
            o.id = id;
            o.managedDatabaseId = managedDatabaseId;
            o.tableStatisticsCollections = tableStatisticsCollections;
            return o;
        }
    }
}