// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabaseAddmTasksFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabaseAddmTasksArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseAddmTasksArgs Empty = new GetManagedDatabaseAddmTasksArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetManagedDatabaseAddmTasksFilterArgs>> filters;

    public Optional<Output<List<GetManagedDatabaseAddmTasksFilterArgs>>> filters() {
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
     * The end of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
     * 
     */
    @Import(name="timeEnd", required=true)
    private Output<String> timeEnd;

    /**
     * @return The end of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
     * 
     */
    public Output<String> timeEnd() {
        return this.timeEnd;
    }

    /**
     * The beginning of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
     * 
     */
    @Import(name="timeStart", required=true)
    private Output<String> timeStart;

    /**
     * @return The beginning of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
     * 
     */
    public Output<String> timeStart() {
        return this.timeStart;
    }

    private GetManagedDatabaseAddmTasksArgs() {}

    private GetManagedDatabaseAddmTasksArgs(GetManagedDatabaseAddmTasksArgs $) {
        this.filters = $.filters;
        this.managedDatabaseId = $.managedDatabaseId;
        this.timeEnd = $.timeEnd;
        this.timeStart = $.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseAddmTasksArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseAddmTasksArgs $;

        public Builder() {
            $ = new GetManagedDatabaseAddmTasksArgs();
        }

        public Builder(GetManagedDatabaseAddmTasksArgs defaults) {
            $ = new GetManagedDatabaseAddmTasksArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetManagedDatabaseAddmTasksFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedDatabaseAddmTasksFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedDatabaseAddmTasksFilterArgs... filters) {
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
         * @param timeEnd The end of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(Output<String> timeEnd) {
            $.timeEnd = timeEnd;
            return this;
        }

        /**
         * @param timeEnd The end of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(String timeEnd) {
            return timeEnd(Output.of(timeEnd));
        }

        /**
         * @param timeStart The beginning of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
         * 
         * @return builder
         * 
         */
        public Builder timeStart(Output<String> timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        /**
         * @param timeStart The beginning of the time range to search for ADDM tasks as defined by date-time RFC3339 format.
         * 
         * @return builder
         * 
         */
        public Builder timeStart(String timeStart) {
            return timeStart(Output.of(timeStart));
        }

        public GetManagedDatabaseAddmTasksArgs build() {
            $.managedDatabaseId = Objects.requireNonNull($.managedDatabaseId, "expected parameter 'managedDatabaseId' to be non-null");
            $.timeEnd = Objects.requireNonNull($.timeEnd, "expected parameter 'timeEnd' to be non-null");
            $.timeStart = Objects.requireNonNull($.timeStart, "expected parameter 'timeStart' to be non-null");
            return $;
        }
    }

}