// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabaseSqlTuningAdvisorTasksFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabaseSqlTuningAdvisorTasksArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseSqlTuningAdvisorTasksArgs Empty = new GetManagedDatabaseSqlTuningAdvisorTasksArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetManagedDatabaseSqlTuningAdvisorTasksFilterArgs>> filters;

    public Optional<Output<List<GetManagedDatabaseSqlTuningAdvisorTasksFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
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
     * The optional query parameter to filter the SQL Tuning Advisor task list by name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The optional query parameter to filter the SQL Tuning Advisor task list by name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
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
     * The optional query parameter to filter the SQL Tuning Advisor task list by status.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The optional query parameter to filter the SQL Tuning Advisor task list by status.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * The optional greater than or equal to query parameter to filter the timestamp.
     * 
     */
    @Import(name="timeGreaterThanOrEqualTo")
    private @Nullable Output<String> timeGreaterThanOrEqualTo;

    /**
     * @return The optional greater than or equal to query parameter to filter the timestamp.
     * 
     */
    public Optional<Output<String>> timeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGreaterThanOrEqualTo);
    }

    /**
     * The optional less than or equal to query parameter to filter the timestamp.
     * 
     */
    @Import(name="timeLessThanOrEqualTo")
    private @Nullable Output<String> timeLessThanOrEqualTo;

    /**
     * @return The optional less than or equal to query parameter to filter the timestamp.
     * 
     */
    public Optional<Output<String>> timeLessThanOrEqualTo() {
        return Optional.ofNullable(this.timeLessThanOrEqualTo);
    }

    private GetManagedDatabaseSqlTuningAdvisorTasksArgs() {}

    private GetManagedDatabaseSqlTuningAdvisorTasksArgs(GetManagedDatabaseSqlTuningAdvisorTasksArgs $) {
        this.filters = $.filters;
        this.managedDatabaseId = $.managedDatabaseId;
        this.name = $.name;
        this.opcNamedCredentialId = $.opcNamedCredentialId;
        this.status = $.status;
        this.timeGreaterThanOrEqualTo = $.timeGreaterThanOrEqualTo;
        this.timeLessThanOrEqualTo = $.timeLessThanOrEqualTo;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseSqlTuningAdvisorTasksArgs $;

        public Builder() {
            $ = new GetManagedDatabaseSqlTuningAdvisorTasksArgs();
        }

        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksArgs defaults) {
            $ = new GetManagedDatabaseSqlTuningAdvisorTasksArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetManagedDatabaseSqlTuningAdvisorTasksFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedDatabaseSqlTuningAdvisorTasksFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedDatabaseSqlTuningAdvisorTasksFilterArgs... filters) {
            return filters(List.of(filters));
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
         * @param name The optional query parameter to filter the SQL Tuning Advisor task list by name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The optional query parameter to filter the SQL Tuning Advisor task list by name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
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
         * @param status The optional query parameter to filter the SQL Tuning Advisor task list by status.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The optional query parameter to filter the SQL Tuning Advisor task list by status.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param timeGreaterThanOrEqualTo The optional greater than or equal to query parameter to filter the timestamp.
         * 
         * @return builder
         * 
         */
        public Builder timeGreaterThanOrEqualTo(@Nullable Output<String> timeGreaterThanOrEqualTo) {
            $.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeGreaterThanOrEqualTo The optional greater than or equal to query parameter to filter the timestamp.
         * 
         * @return builder
         * 
         */
        public Builder timeGreaterThanOrEqualTo(String timeGreaterThanOrEqualTo) {
            return timeGreaterThanOrEqualTo(Output.of(timeGreaterThanOrEqualTo));
        }

        /**
         * @param timeLessThanOrEqualTo The optional less than or equal to query parameter to filter the timestamp.
         * 
         * @return builder
         * 
         */
        public Builder timeLessThanOrEqualTo(@Nullable Output<String> timeLessThanOrEqualTo) {
            $.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
            return this;
        }

        /**
         * @param timeLessThanOrEqualTo The optional less than or equal to query parameter to filter the timestamp.
         * 
         * @return builder
         * 
         */
        public Builder timeLessThanOrEqualTo(String timeLessThanOrEqualTo) {
            return timeLessThanOrEqualTo(Output.of(timeLessThanOrEqualTo));
        }

        public GetManagedDatabaseSqlTuningAdvisorTasksArgs build() {
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningAdvisorTasksArgs", "managedDatabaseId");
            }
            return $;
        }
    }

}
