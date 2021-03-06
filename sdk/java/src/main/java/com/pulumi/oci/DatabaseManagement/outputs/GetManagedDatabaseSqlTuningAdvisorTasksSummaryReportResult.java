// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult {
    private final @Nullable String beginExecIdGreaterThanOrEqualTo;
    private final @Nullable String endExecIdLessThanOrEqualTo;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of object findings related to indexes.
     * 
     */
    private final List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding> indexFindings;
    private final String managedDatabaseId;
    /**
     * @return The list of object findings related to statistics.
     * 
     */
    private final List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding> objectStatFindings;
    private final @Nullable String searchPeriod;
    private final String sqlTuningAdvisorTaskId;
    /**
     * @return The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
     * 
     */
    private final List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic> statistics;
    /**
     * @return The general information regarding the SQL Tuning Advisor task.
     * 
     */
    private final List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo> taskInfos;
    private final @Nullable String timeGreaterThanOrEqualTo;
    private final @Nullable String timeLessThanOrEqualTo;

    @CustomType.Constructor
    private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult(
        @CustomType.Parameter("beginExecIdGreaterThanOrEqualTo") @Nullable String beginExecIdGreaterThanOrEqualTo,
        @CustomType.Parameter("endExecIdLessThanOrEqualTo") @Nullable String endExecIdLessThanOrEqualTo,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("indexFindings") List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding> indexFindings,
        @CustomType.Parameter("managedDatabaseId") String managedDatabaseId,
        @CustomType.Parameter("objectStatFindings") List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding> objectStatFindings,
        @CustomType.Parameter("searchPeriod") @Nullable String searchPeriod,
        @CustomType.Parameter("sqlTuningAdvisorTaskId") String sqlTuningAdvisorTaskId,
        @CustomType.Parameter("statistics") List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic> statistics,
        @CustomType.Parameter("taskInfos") List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo> taskInfos,
        @CustomType.Parameter("timeGreaterThanOrEqualTo") @Nullable String timeGreaterThanOrEqualTo,
        @CustomType.Parameter("timeLessThanOrEqualTo") @Nullable String timeLessThanOrEqualTo) {
        this.beginExecIdGreaterThanOrEqualTo = beginExecIdGreaterThanOrEqualTo;
        this.endExecIdLessThanOrEqualTo = endExecIdLessThanOrEqualTo;
        this.id = id;
        this.indexFindings = indexFindings;
        this.managedDatabaseId = managedDatabaseId;
        this.objectStatFindings = objectStatFindings;
        this.searchPeriod = searchPeriod;
        this.sqlTuningAdvisorTaskId = sqlTuningAdvisorTaskId;
        this.statistics = statistics;
        this.taskInfos = taskInfos;
        this.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
        this.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
    }

    public Optional<String> beginExecIdGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.beginExecIdGreaterThanOrEqualTo);
    }
    public Optional<String> endExecIdLessThanOrEqualTo() {
        return Optional.ofNullable(this.endExecIdLessThanOrEqualTo);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of object findings related to indexes.
     * 
     */
    public List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding> indexFindings() {
        return this.indexFindings;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * @return The list of object findings related to statistics.
     * 
     */
    public List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding> objectStatFindings() {
        return this.objectStatFindings;
    }
    public Optional<String> searchPeriod() {
        return Optional.ofNullable(this.searchPeriod);
    }
    public String sqlTuningAdvisorTaskId() {
        return this.sqlTuningAdvisorTaskId;
    }
    /**
     * @return The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
     * 
     */
    public List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic> statistics() {
        return this.statistics;
    }
    /**
     * @return The general information regarding the SQL Tuning Advisor task.
     * 
     */
    public List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo> taskInfos() {
        return this.taskInfos;
    }
    public Optional<String> timeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGreaterThanOrEqualTo);
    }
    public Optional<String> timeLessThanOrEqualTo() {
        return Optional.ofNullable(this.timeLessThanOrEqualTo);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String beginExecIdGreaterThanOrEqualTo;
        private @Nullable String endExecIdLessThanOrEqualTo;
        private String id;
        private List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding> indexFindings;
        private String managedDatabaseId;
        private List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding> objectStatFindings;
        private @Nullable String searchPeriod;
        private String sqlTuningAdvisorTaskId;
        private List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic> statistics;
        private List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo> taskInfos;
        private @Nullable String timeGreaterThanOrEqualTo;
        private @Nullable String timeLessThanOrEqualTo;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.beginExecIdGreaterThanOrEqualTo = defaults.beginExecIdGreaterThanOrEqualTo;
    	      this.endExecIdLessThanOrEqualTo = defaults.endExecIdLessThanOrEqualTo;
    	      this.id = defaults.id;
    	      this.indexFindings = defaults.indexFindings;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.objectStatFindings = defaults.objectStatFindings;
    	      this.searchPeriod = defaults.searchPeriod;
    	      this.sqlTuningAdvisorTaskId = defaults.sqlTuningAdvisorTaskId;
    	      this.statistics = defaults.statistics;
    	      this.taskInfos = defaults.taskInfos;
    	      this.timeGreaterThanOrEqualTo = defaults.timeGreaterThanOrEqualTo;
    	      this.timeLessThanOrEqualTo = defaults.timeLessThanOrEqualTo;
        }

        public Builder beginExecIdGreaterThanOrEqualTo(@Nullable String beginExecIdGreaterThanOrEqualTo) {
            this.beginExecIdGreaterThanOrEqualTo = beginExecIdGreaterThanOrEqualTo;
            return this;
        }
        public Builder endExecIdLessThanOrEqualTo(@Nullable String endExecIdLessThanOrEqualTo) {
            this.endExecIdLessThanOrEqualTo = endExecIdLessThanOrEqualTo;
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder indexFindings(List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding> indexFindings) {
            this.indexFindings = Objects.requireNonNull(indexFindings);
            return this;
        }
        public Builder indexFindings(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding... indexFindings) {
            return indexFindings(List.of(indexFindings));
        }
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        public Builder objectStatFindings(List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding> objectStatFindings) {
            this.objectStatFindings = Objects.requireNonNull(objectStatFindings);
            return this;
        }
        public Builder objectStatFindings(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding... objectStatFindings) {
            return objectStatFindings(List.of(objectStatFindings));
        }
        public Builder searchPeriod(@Nullable String searchPeriod) {
            this.searchPeriod = searchPeriod;
            return this;
        }
        public Builder sqlTuningAdvisorTaskId(String sqlTuningAdvisorTaskId) {
            this.sqlTuningAdvisorTaskId = Objects.requireNonNull(sqlTuningAdvisorTaskId);
            return this;
        }
        public Builder statistics(List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic> statistics) {
            this.statistics = Objects.requireNonNull(statistics);
            return this;
        }
        public Builder statistics(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic... statistics) {
            return statistics(List.of(statistics));
        }
        public Builder taskInfos(List<GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo> taskInfos) {
            this.taskInfos = Objects.requireNonNull(taskInfos);
            return this;
        }
        public Builder taskInfos(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo... taskInfos) {
            return taskInfos(List.of(taskInfos));
        }
        public Builder timeGreaterThanOrEqualTo(@Nullable String timeGreaterThanOrEqualTo) {
            this.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            return this;
        }
        public Builder timeLessThanOrEqualTo(@Nullable String timeLessThanOrEqualTo) {
            this.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
            return this;
        }        public GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult build() {
            return new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult(beginExecIdGreaterThanOrEqualTo, endExecIdLessThanOrEqualTo, id, indexFindings, managedDatabaseId, objectStatFindings, searchPeriod, sqlTuningAdvisorTaskId, statistics, taskInfos, timeGreaterThanOrEqualTo, timeLessThanOrEqualTo);
        }
    }
}
