// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabasesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabasesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabasesArgs Empty = new GetManagedDatabasesArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return Managed Databases of the specified deployment type.
     * 
     */
    @Import(name="deploymentType")
    private @Nullable Output<String> deploymentType;

    /**
     * @return A filter to return Managed Databases of the specified deployment type.
     * 
     */
    public Optional<Output<String>> deploymentType() {
        return Optional.ofNullable(this.deploymentType);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetManagedDatabasesFilterArgs>> filters;

    public Optional<Output<List<GetManagedDatabasesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The identifier of the resource.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The identifier of the resource.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return Managed Databases with the specified management option.
     * 
     */
    @Import(name="managementOption")
    private @Nullable Output<String> managementOption;

    /**
     * @return A filter to return Managed Databases with the specified management option.
     * 
     */
    public Optional<Output<String>> managementOption() {
        return Optional.ofNullable(this.managementOption);
    }

    /**
     * A filter to return only resources that match the entire name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private GetManagedDatabasesArgs() {}

    private GetManagedDatabasesArgs(GetManagedDatabasesArgs $) {
        this.compartmentId = $.compartmentId;
        this.deploymentType = $.deploymentType;
        this.filters = $.filters;
        this.id = $.id;
        this.managementOption = $.managementOption;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabasesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabasesArgs $;

        public Builder() {
            $ = new GetManagedDatabasesArgs();
        }

        public Builder(GetManagedDatabasesArgs defaults) {
            $ = new GetManagedDatabasesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param deploymentType A filter to return Managed Databases of the specified deployment type.
         * 
         * @return builder
         * 
         */
        public Builder deploymentType(@Nullable Output<String> deploymentType) {
            $.deploymentType = deploymentType;
            return this;
        }

        /**
         * @param deploymentType A filter to return Managed Databases of the specified deployment type.
         * 
         * @return builder
         * 
         */
        public Builder deploymentType(String deploymentType) {
            return deploymentType(Output.of(deploymentType));
        }

        public Builder filters(@Nullable Output<List<GetManagedDatabasesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedDatabasesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedDatabasesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The identifier of the resource.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The identifier of the resource.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param managementOption A filter to return Managed Databases with the specified management option.
         * 
         * @return builder
         * 
         */
        public Builder managementOption(@Nullable Output<String> managementOption) {
            $.managementOption = managementOption;
            return this;
        }

        /**
         * @param managementOption A filter to return Managed Databases with the specified management option.
         * 
         * @return builder
         * 
         */
        public Builder managementOption(String managementOption) {
            return managementOption(Output.of(managementOption));
        }

        /**
         * @param name A filter to return only resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetManagedDatabasesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}