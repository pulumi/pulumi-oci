// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabasesAsmPropertiesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabasesAsmPropertiesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabasesAsmPropertiesPlainArgs Empty = new GetManagedDatabasesAsmPropertiesPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetManagedDatabasesAsmPropertiesFilter> filters;

    public Optional<List<GetManagedDatabasesAsmPropertiesFilter>> filters() {
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

    /**
     * A filter to return only resources that match the entire name.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    private GetManagedDatabasesAsmPropertiesPlainArgs() {}

    private GetManagedDatabasesAsmPropertiesPlainArgs(GetManagedDatabasesAsmPropertiesPlainArgs $) {
        this.filters = $.filters;
        this.managedDatabaseId = $.managedDatabaseId;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabasesAsmPropertiesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabasesAsmPropertiesPlainArgs $;

        public Builder() {
            $ = new GetManagedDatabasesAsmPropertiesPlainArgs();
        }

        public Builder(GetManagedDatabasesAsmPropertiesPlainArgs defaults) {
            $ = new GetManagedDatabasesAsmPropertiesPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetManagedDatabasesAsmPropertiesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetManagedDatabasesAsmPropertiesFilter... filters) {
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

        /**
         * @param name A filter to return only resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        public GetManagedDatabasesAsmPropertiesPlainArgs build() {
            $.managedDatabaseId = Objects.requireNonNull($.managedDatabaseId, "expected parameter 'managedDatabaseId' to be non-null");
            return $;
        }
    }

}