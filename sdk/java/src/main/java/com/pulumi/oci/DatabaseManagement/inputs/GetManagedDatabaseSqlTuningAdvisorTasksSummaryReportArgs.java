// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs Empty = new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs();

    /**
     * The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    @Import(name="beginExecIdGreaterThanOrEqualTo")
    private @Nullable Output<String> beginExecIdGreaterThanOrEqualTo;

    /**
     * @return The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    public Optional<Output<String>> beginExecIdGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.beginExecIdGreaterThanOrEqualTo);
    }

    /**
     * The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    @Import(name="endExecIdLessThanOrEqualTo")
    private @Nullable Output<String> endExecIdLessThanOrEqualTo;

    /**
     * @return The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    public Optional<Output<String>> endExecIdLessThanOrEqualTo() {
        return Optional.ofNullable(this.endExecIdLessThanOrEqualTo);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Output<String> managedDatabaseId() {
        return this.managedDatabaseId;
    }

    /**
     * How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    @Import(name="searchPeriod")
    private @Nullable Output<String> searchPeriod;

    /**
     * @return How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    public Optional<Output<String>> searchPeriod() {
        return Optional.ofNullable(this.searchPeriod);
    }

    /**
     * The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="sqlTuningAdvisorTaskId", required=true)
    private Output<String> sqlTuningAdvisorTaskId;

    /**
     * @return The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> sqlTuningAdvisorTaskId() {
        return this.sqlTuningAdvisorTaskId;
    }

    /**
     * The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    @Import(name="timeGreaterThanOrEqualTo")
    private @Nullable Output<String> timeGreaterThanOrEqualTo;

    /**
     * @return The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    public Optional<Output<String>> timeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGreaterThanOrEqualTo);
    }

    /**
     * The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    @Import(name="timeLessThanOrEqualTo")
    private @Nullable Output<String> timeLessThanOrEqualTo;

    /**
     * @return The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
     * 
     */
    public Optional<Output<String>> timeLessThanOrEqualTo() {
        return Optional.ofNullable(this.timeLessThanOrEqualTo);
    }

    private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs() {}

    private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs $) {
        this.beginExecIdGreaterThanOrEqualTo = $.beginExecIdGreaterThanOrEqualTo;
        this.endExecIdLessThanOrEqualTo = $.endExecIdLessThanOrEqualTo;
        this.managedDatabaseId = $.managedDatabaseId;
        this.searchPeriod = $.searchPeriod;
        this.sqlTuningAdvisorTaskId = $.sqlTuningAdvisorTaskId;
        this.timeGreaterThanOrEqualTo = $.timeGreaterThanOrEqualTo;
        this.timeLessThanOrEqualTo = $.timeLessThanOrEqualTo;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs $;

        public Builder() {
            $ = new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs();
        }

        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs defaults) {
            $ = new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param beginExecIdGreaterThanOrEqualTo The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder beginExecIdGreaterThanOrEqualTo(@Nullable Output<String> beginExecIdGreaterThanOrEqualTo) {
            $.beginExecIdGreaterThanOrEqualTo = beginExecIdGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param beginExecIdGreaterThanOrEqualTo The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder beginExecIdGreaterThanOrEqualTo(String beginExecIdGreaterThanOrEqualTo) {
            return beginExecIdGreaterThanOrEqualTo(Output.of(beginExecIdGreaterThanOrEqualTo));
        }

        /**
         * @param endExecIdLessThanOrEqualTo The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder endExecIdLessThanOrEqualTo(@Nullable Output<String> endExecIdLessThanOrEqualTo) {
            $.endExecIdLessThanOrEqualTo = endExecIdLessThanOrEqualTo;
            return this;
        }

        /**
         * @param endExecIdLessThanOrEqualTo The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder endExecIdLessThanOrEqualTo(String endExecIdLessThanOrEqualTo) {
            return endExecIdLessThanOrEqualTo(Output.of(endExecIdLessThanOrEqualTo));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(Output<String> managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            return managedDatabaseId(Output.of(managedDatabaseId));
        }

        /**
         * @param searchPeriod How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder searchPeriod(@Nullable Output<String> searchPeriod) {
            $.searchPeriod = searchPeriod;
            return this;
        }

        /**
         * @param searchPeriod How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder searchPeriod(String searchPeriod) {
            return searchPeriod(Output.of(searchPeriod));
        }

        /**
         * @param sqlTuningAdvisorTaskId The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder sqlTuningAdvisorTaskId(Output<String> sqlTuningAdvisorTaskId) {
            $.sqlTuningAdvisorTaskId = sqlTuningAdvisorTaskId;
            return this;
        }

        /**
         * @param sqlTuningAdvisorTaskId The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder sqlTuningAdvisorTaskId(String sqlTuningAdvisorTaskId) {
            return sqlTuningAdvisorTaskId(Output.of(sqlTuningAdvisorTaskId));
        }

        /**
         * @param timeGreaterThanOrEqualTo The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder timeGreaterThanOrEqualTo(@Nullable Output<String> timeGreaterThanOrEqualTo) {
            $.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeGreaterThanOrEqualTo The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder timeGreaterThanOrEqualTo(String timeGreaterThanOrEqualTo) {
            return timeGreaterThanOrEqualTo(Output.of(timeGreaterThanOrEqualTo));
        }

        /**
         * @param timeLessThanOrEqualTo The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder timeLessThanOrEqualTo(@Nullable Output<String> timeLessThanOrEqualTo) {
            $.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
            return this;
        }

        /**
         * @param timeLessThanOrEqualTo The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
         * 
         * @return builder
         * 
         */
        public Builder timeLessThanOrEqualTo(String timeLessThanOrEqualTo) {
            return timeLessThanOrEqualTo(Output.of(timeLessThanOrEqualTo));
        }

        public GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs build() {
            $.managedDatabaseId = Objects.requireNonNull($.managedDatabaseId, "expected parameter 'managedDatabaseId' to be non-null");
            $.sqlTuningAdvisorTaskId = Objects.requireNonNull($.sqlTuningAdvisorTaskId, "expected parameter 'sqlTuningAdvisorTaskId' to be non-null");
            return $;
        }
    }

}