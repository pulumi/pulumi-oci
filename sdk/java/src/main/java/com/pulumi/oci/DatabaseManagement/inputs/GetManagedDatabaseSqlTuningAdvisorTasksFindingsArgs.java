// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabaseSqlTuningAdvisorTasksFindingsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs Empty = new GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs();

    /**
     * The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task.
     * 
     */
    @Import(name="beginExecId")
    private @Nullable Output<String> beginExecId;

    /**
     * @return The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task.
     * 
     */
    public Optional<Output<String>> beginExecId() {
        return Optional.ofNullable(this.beginExecId);
    }

    /**
     * The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task.
     * 
     */
    @Import(name="endExecId")
    private @Nullable Output<String> endExecId;

    /**
     * @return The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task.
     * 
     */
    public Optional<Output<String>> endExecId() {
        return Optional.ofNullable(this.endExecId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetManagedDatabaseSqlTuningAdvisorTasksFindingsFilterArgs>> filters;

    public Optional<Output<List<GetManagedDatabaseSqlTuningAdvisorTasksFindingsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The filter used to display specific findings in the report.
     * 
     */
    @Import(name="findingFilter")
    private @Nullable Output<String> findingFilter;

    /**
     * @return The filter used to display specific findings in the report.
     * 
     */
    public Optional<Output<String>> findingFilter() {
        return Optional.ofNullable(this.findingFilter);
    }

    /**
     * The hash value of the index table name.
     * 
     */
    @Import(name="indexHashFilter")
    private @Nullable Output<String> indexHashFilter;

    /**
     * @return The hash value of the index table name.
     * 
     */
    public Optional<Output<String>> indexHashFilter() {
        return Optional.ofNullable(this.indexHashFilter);
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
     * The OCID of the Named Credential.
     * 
     */
    @Import(name="opcNamedCredentialId")
    private @Nullable Output<String> opcNamedCredentialId;

    /**
     * @return The OCID of the Named Credential.
     * 
     */
    public Optional<Output<String>> opcNamedCredentialId() {
        return Optional.ofNullable(this.opcNamedCredentialId);
    }

    /**
     * The search period during which the API will search for begin and end exec id, if not supplied. Unused if beginExecId and endExecId optional query params are both supplied.
     * 
     */
    @Import(name="searchPeriod")
    private @Nullable Output<String> searchPeriod;

    /**
     * @return The search period during which the API will search for begin and end exec id, if not supplied. Unused if beginExecId and endExecId optional query params are both supplied.
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
     * The hash value of the object for the statistic finding search.
     * 
     */
    @Import(name="statsHashFilter")
    private @Nullable Output<String> statsHashFilter;

    /**
     * @return The hash value of the object for the statistic finding search.
     * 
     */
    public Optional<Output<String>> statsHashFilter() {
        return Optional.ofNullable(this.statsHashFilter);
    }

    private GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs() {}

    private GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs(GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs $) {
        this.beginExecId = $.beginExecId;
        this.endExecId = $.endExecId;
        this.filters = $.filters;
        this.findingFilter = $.findingFilter;
        this.indexHashFilter = $.indexHashFilter;
        this.managedDatabaseId = $.managedDatabaseId;
        this.opcNamedCredentialId = $.opcNamedCredentialId;
        this.searchPeriod = $.searchPeriod;
        this.sqlTuningAdvisorTaskId = $.sqlTuningAdvisorTaskId;
        this.statsHashFilter = $.statsHashFilter;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs $;

        public Builder() {
            $ = new GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs();
        }

        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs defaults) {
            $ = new GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param beginExecId The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task.
         * 
         * @return builder
         * 
         */
        public Builder beginExecId(@Nullable Output<String> beginExecId) {
            $.beginExecId = beginExecId;
            return this;
        }

        /**
         * @param beginExecId The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task.
         * 
         * @return builder
         * 
         */
        public Builder beginExecId(String beginExecId) {
            return beginExecId(Output.of(beginExecId));
        }

        /**
         * @param endExecId The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task.
         * 
         * @return builder
         * 
         */
        public Builder endExecId(@Nullable Output<String> endExecId) {
            $.endExecId = endExecId;
            return this;
        }

        /**
         * @param endExecId The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task.
         * 
         * @return builder
         * 
         */
        public Builder endExecId(String endExecId) {
            return endExecId(Output.of(endExecId));
        }

        public Builder filters(@Nullable Output<List<GetManagedDatabaseSqlTuningAdvisorTasksFindingsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedDatabaseSqlTuningAdvisorTasksFindingsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedDatabaseSqlTuningAdvisorTasksFindingsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param findingFilter The filter used to display specific findings in the report.
         * 
         * @return builder
         * 
         */
        public Builder findingFilter(@Nullable Output<String> findingFilter) {
            $.findingFilter = findingFilter;
            return this;
        }

        /**
         * @param findingFilter The filter used to display specific findings in the report.
         * 
         * @return builder
         * 
         */
        public Builder findingFilter(String findingFilter) {
            return findingFilter(Output.of(findingFilter));
        }

        /**
         * @param indexHashFilter The hash value of the index table name.
         * 
         * @return builder
         * 
         */
        public Builder indexHashFilter(@Nullable Output<String> indexHashFilter) {
            $.indexHashFilter = indexHashFilter;
            return this;
        }

        /**
         * @param indexHashFilter The hash value of the index table name.
         * 
         * @return builder
         * 
         */
        public Builder indexHashFilter(String indexHashFilter) {
            return indexHashFilter(Output.of(indexHashFilter));
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
         * @param opcNamedCredentialId The OCID of the Named Credential.
         * 
         * @return builder
         * 
         */
        public Builder opcNamedCredentialId(@Nullable Output<String> opcNamedCredentialId) {
            $.opcNamedCredentialId = opcNamedCredentialId;
            return this;
        }

        /**
         * @param opcNamedCredentialId The OCID of the Named Credential.
         * 
         * @return builder
         * 
         */
        public Builder opcNamedCredentialId(String opcNamedCredentialId) {
            return opcNamedCredentialId(Output.of(opcNamedCredentialId));
        }

        /**
         * @param searchPeriod The search period during which the API will search for begin and end exec id, if not supplied. Unused if beginExecId and endExecId optional query params are both supplied.
         * 
         * @return builder
         * 
         */
        public Builder searchPeriod(@Nullable Output<String> searchPeriod) {
            $.searchPeriod = searchPeriod;
            return this;
        }

        /**
         * @param searchPeriod The search period during which the API will search for begin and end exec id, if not supplied. Unused if beginExecId and endExecId optional query params are both supplied.
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
         * @param statsHashFilter The hash value of the object for the statistic finding search.
         * 
         * @return builder
         * 
         */
        public Builder statsHashFilter(@Nullable Output<String> statsHashFilter) {
            $.statsHashFilter = statsHashFilter;
            return this;
        }

        /**
         * @param statsHashFilter The hash value of the object for the statistic finding search.
         * 
         * @return builder
         * 
         */
        public Builder statsHashFilter(String statsHashFilter) {
            return statsHashFilter(Output.of(statsHashFilter));
        }

        public GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs build() {
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs", "managedDatabaseId");
            }
            if ($.sqlTuningAdvisorTaskId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksFindingsArgs", "sqlTuningAdvisorTaskId");
            }
            return $;
        }
    }

}
