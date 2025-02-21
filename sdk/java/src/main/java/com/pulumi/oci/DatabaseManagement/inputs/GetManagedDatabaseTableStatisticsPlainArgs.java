// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabaseTableStatisticsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabaseTableStatisticsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseTableStatisticsPlainArgs Empty = new GetManagedDatabaseTableStatisticsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetManagedDatabaseTableStatisticsFilter> filters;

    public Optional<List<GetManagedDatabaseTableStatisticsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private String managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }

    private GetManagedDatabaseTableStatisticsPlainArgs() {}

    private GetManagedDatabaseTableStatisticsPlainArgs(GetManagedDatabaseTableStatisticsPlainArgs $) {
        this.filters = $.filters;
        this.managedDatabaseId = $.managedDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseTableStatisticsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseTableStatisticsPlainArgs $;

        public Builder() {
            $ = new GetManagedDatabaseTableStatisticsPlainArgs();
        }

        public Builder(GetManagedDatabaseTableStatisticsPlainArgs defaults) {
            $ = new GetManagedDatabaseTableStatisticsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetManagedDatabaseTableStatisticsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetManagedDatabaseTableStatisticsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        public GetManagedDatabaseTableStatisticsPlainArgs build() {
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseTableStatisticsPlainArgs", "managedDatabaseId");
            }
            return $;
        }
    }

}
