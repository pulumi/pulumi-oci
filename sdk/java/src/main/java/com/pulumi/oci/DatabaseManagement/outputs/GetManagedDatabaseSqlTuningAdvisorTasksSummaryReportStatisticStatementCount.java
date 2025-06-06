// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount {
    /**
     * @return The number of distinct SQL statements.
     * 
     */
    private Integer distinctSql;
    /**
     * @return The number of distinct SQL statements with errors.
     * 
     */
    private Integer errorCount;
    /**
     * @return The number of distinct SQL statements with findings.
     * 
     */
    private Integer findingCount;
    /**
     * @return The total number of SQL statements.
     * 
     */
    private Integer totalSql;

    private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount() {}
    /**
     * @return The number of distinct SQL statements.
     * 
     */
    public Integer distinctSql() {
        return this.distinctSql;
    }
    /**
     * @return The number of distinct SQL statements with errors.
     * 
     */
    public Integer errorCount() {
        return this.errorCount;
    }
    /**
     * @return The number of distinct SQL statements with findings.
     * 
     */
    public Integer findingCount() {
        return this.findingCount;
    }
    /**
     * @return The total number of SQL statements.
     * 
     */
    public Integer totalSql() {
        return this.totalSql;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer distinctSql;
        private Integer errorCount;
        private Integer findingCount;
        private Integer totalSql;
        public Builder() {}
        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.distinctSql = defaults.distinctSql;
    	      this.errorCount = defaults.errorCount;
    	      this.findingCount = defaults.findingCount;
    	      this.totalSql = defaults.totalSql;
        }

        @CustomType.Setter
        public Builder distinctSql(Integer distinctSql) {
            if (distinctSql == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount", "distinctSql");
            }
            this.distinctSql = distinctSql;
            return this;
        }
        @CustomType.Setter
        public Builder errorCount(Integer errorCount) {
            if (errorCount == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount", "errorCount");
            }
            this.errorCount = errorCount;
            return this;
        }
        @CustomType.Setter
        public Builder findingCount(Integer findingCount) {
            if (findingCount == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount", "findingCount");
            }
            this.findingCount = findingCount;
            return this;
        }
        @CustomType.Setter
        public Builder totalSql(Integer totalSql) {
            if (totalSql == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount", "totalSql");
            }
            this.totalSql = totalSql;
            return this;
        }
        public GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount build() {
            final var _resultValue = new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticStatementCount();
            _resultValue.distinctSql = distinctSql;
            _resultValue.errorCount = errorCount;
            _resultValue.findingCount = findingCount;
            _resultValue.totalSql = totalSql;
            return _resultValue;
        }
    }
}
