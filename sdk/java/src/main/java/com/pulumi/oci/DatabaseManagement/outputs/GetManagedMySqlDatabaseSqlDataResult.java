// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseSqlDataFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseSqlDataMySqlDataCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedMySqlDatabaseSqlDataResult {
    private String endTime;
    private @Nullable String filterColumn;
    private @Nullable List<GetManagedMySqlDatabaseSqlDataFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedMySqlDatabaseId;
    /**
     * @return The list of my_sql_data_collection.
     * 
     */
    private List<GetManagedMySqlDatabaseSqlDataMySqlDataCollection> mySqlDataCollections;
    private String startTime;

    private GetManagedMySqlDatabaseSqlDataResult() {}
    public String endTime() {
        return this.endTime;
    }
    public Optional<String> filterColumn() {
        return Optional.ofNullable(this.filterColumn);
    }
    public List<GetManagedMySqlDatabaseSqlDataFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String managedMySqlDatabaseId() {
        return this.managedMySqlDatabaseId;
    }
    /**
     * @return The list of my_sql_data_collection.
     * 
     */
    public List<GetManagedMySqlDatabaseSqlDataMySqlDataCollection> mySqlDataCollections() {
        return this.mySqlDataCollections;
    }
    public String startTime() {
        return this.startTime;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedMySqlDatabaseSqlDataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String endTime;
        private @Nullable String filterColumn;
        private @Nullable List<GetManagedMySqlDatabaseSqlDataFilter> filters;
        private String id;
        private String managedMySqlDatabaseId;
        private List<GetManagedMySqlDatabaseSqlDataMySqlDataCollection> mySqlDataCollections;
        private String startTime;
        public Builder() {}
        public Builder(GetManagedMySqlDatabaseSqlDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.endTime = defaults.endTime;
    	      this.filterColumn = defaults.filterColumn;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedMySqlDatabaseId = defaults.managedMySqlDatabaseId;
    	      this.mySqlDataCollections = defaults.mySqlDataCollections;
    	      this.startTime = defaults.startTime;
        }

        @CustomType.Setter
        public Builder endTime(String endTime) {
            if (endTime == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseSqlDataResult", "endTime");
            }
            this.endTime = endTime;
            return this;
        }
        @CustomType.Setter
        public Builder filterColumn(@Nullable String filterColumn) {

            this.filterColumn = filterColumn;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedMySqlDatabaseSqlDataFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedMySqlDatabaseSqlDataFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseSqlDataResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managedMySqlDatabaseId(String managedMySqlDatabaseId) {
            if (managedMySqlDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseSqlDataResult", "managedMySqlDatabaseId");
            }
            this.managedMySqlDatabaseId = managedMySqlDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder mySqlDataCollections(List<GetManagedMySqlDatabaseSqlDataMySqlDataCollection> mySqlDataCollections) {
            if (mySqlDataCollections == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseSqlDataResult", "mySqlDataCollections");
            }
            this.mySqlDataCollections = mySqlDataCollections;
            return this;
        }
        public Builder mySqlDataCollections(GetManagedMySqlDatabaseSqlDataMySqlDataCollection... mySqlDataCollections) {
            return mySqlDataCollections(List.of(mySqlDataCollections));
        }
        @CustomType.Setter
        public Builder startTime(String startTime) {
            if (startTime == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseSqlDataResult", "startTime");
            }
            this.startTime = startTime;
            return this;
        }
        public GetManagedMySqlDatabaseSqlDataResult build() {
            final var _resultValue = new GetManagedMySqlDatabaseSqlDataResult();
            _resultValue.endTime = endTime;
            _resultValue.filterColumn = filterColumn;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.managedMySqlDatabaseId = managedMySqlDatabaseId;
            _resultValue.mySqlDataCollections = mySqlDataCollections;
            _resultValue.startTime = startTime;
            return _resultValue;
        }
    }
}
