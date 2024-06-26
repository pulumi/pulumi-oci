// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseSqlTuningAdvisorTasksFindingItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabaseSqlTuningAdvisorTasksFindingResult {
    private @Nullable String beginExecId;
    private @Nullable String endExecId;
    private @Nullable String findingFilter;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String indexHashFilter;
    /**
     * @return An array of the findings for a tuning task.
     * 
     */
    private List<GetManagedDatabaseSqlTuningAdvisorTasksFindingItem> items;
    private String managedDatabaseId;
    private @Nullable String searchPeriod;
    /**
     * @return The unique identifier of the SQL Tuning Advisor task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String sqlTuningAdvisorTaskId;
    private @Nullable String statsHashFilter;

    private GetManagedDatabaseSqlTuningAdvisorTasksFindingResult() {}
    public Optional<String> beginExecId() {
        return Optional.ofNullable(this.beginExecId);
    }
    public Optional<String> endExecId() {
        return Optional.ofNullable(this.endExecId);
    }
    public Optional<String> findingFilter() {
        return Optional.ofNullable(this.findingFilter);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> indexHashFilter() {
        return Optional.ofNullable(this.indexHashFilter);
    }
    /**
     * @return An array of the findings for a tuning task.
     * 
     */
    public List<GetManagedDatabaseSqlTuningAdvisorTasksFindingItem> items() {
        return this.items;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    public Optional<String> searchPeriod() {
        return Optional.ofNullable(this.searchPeriod);
    }
    /**
     * @return The unique identifier of the SQL Tuning Advisor task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String sqlTuningAdvisorTaskId() {
        return this.sqlTuningAdvisorTaskId;
    }
    public Optional<String> statsHashFilter() {
        return Optional.ofNullable(this.statsHashFilter);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksFindingResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String beginExecId;
        private @Nullable String endExecId;
        private @Nullable String findingFilter;
        private String id;
        private @Nullable String indexHashFilter;
        private List<GetManagedDatabaseSqlTuningAdvisorTasksFindingItem> items;
        private String managedDatabaseId;
        private @Nullable String searchPeriod;
        private String sqlTuningAdvisorTaskId;
        private @Nullable String statsHashFilter;
        public Builder() {}
        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksFindingResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.beginExecId = defaults.beginExecId;
    	      this.endExecId = defaults.endExecId;
    	      this.findingFilter = defaults.findingFilter;
    	      this.id = defaults.id;
    	      this.indexHashFilter = defaults.indexHashFilter;
    	      this.items = defaults.items;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.searchPeriod = defaults.searchPeriod;
    	      this.sqlTuningAdvisorTaskId = defaults.sqlTuningAdvisorTaskId;
    	      this.statsHashFilter = defaults.statsHashFilter;
        }

        @CustomType.Setter
        public Builder beginExecId(@Nullable String beginExecId) {

            this.beginExecId = beginExecId;
            return this;
        }
        @CustomType.Setter
        public Builder endExecId(@Nullable String endExecId) {

            this.endExecId = endExecId;
            return this;
        }
        @CustomType.Setter
        public Builder findingFilter(@Nullable String findingFilter) {

            this.findingFilter = findingFilter;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksFindingResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder indexHashFilter(@Nullable String indexHashFilter) {

            this.indexHashFilter = indexHashFilter;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetManagedDatabaseSqlTuningAdvisorTasksFindingItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksFindingResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetManagedDatabaseSqlTuningAdvisorTasksFindingItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            if (managedDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksFindingResult", "managedDatabaseId");
            }
            this.managedDatabaseId = managedDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder searchPeriod(@Nullable String searchPeriod) {

            this.searchPeriod = searchPeriod;
            return this;
        }
        @CustomType.Setter
        public Builder sqlTuningAdvisorTaskId(String sqlTuningAdvisorTaskId) {
            if (sqlTuningAdvisorTaskId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksFindingResult", "sqlTuningAdvisorTaskId");
            }
            this.sqlTuningAdvisorTaskId = sqlTuningAdvisorTaskId;
            return this;
        }
        @CustomType.Setter
        public Builder statsHashFilter(@Nullable String statsHashFilter) {

            this.statsHashFilter = statsHashFilter;
            return this;
        }
        public GetManagedDatabaseSqlTuningAdvisorTasksFindingResult build() {
            final var _resultValue = new GetManagedDatabaseSqlTuningAdvisorTasksFindingResult();
            _resultValue.beginExecId = beginExecId;
            _resultValue.endExecId = endExecId;
            _resultValue.findingFilter = findingFilter;
            _resultValue.id = id;
            _resultValue.indexHashFilter = indexHashFilter;
            _resultValue.items = items;
            _resultValue.managedDatabaseId = managedDatabaseId;
            _resultValue.searchPeriod = searchPeriod;
            _resultValue.sqlTuningAdvisorTaskId = sqlTuningAdvisorTaskId;
            _resultValue.statsHashFilter = statsHashFilter;
            return _resultValue;
        }
    }
}
