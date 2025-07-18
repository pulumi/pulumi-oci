// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.inputs.GetInternalOccmDemandSignalItemsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetInternalOccmDemandSignalItemsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInternalOccmDemandSignalItemsArgs Empty = new GetInternalOccmDemandSignalItemsArgs();

    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A query parameter to filter the list of demand signal details based on the namespace.
     * 
     */
    @Import(name="demandSignalNamespace")
    private @Nullable Output<String> demandSignalNamespace;

    /**
     * @return A query parameter to filter the list of demand signal details based on the namespace.
     * 
     */
    public Optional<Output<String>> demandSignalNamespace() {
        return Optional.ofNullable(this.demandSignalNamespace);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetInternalOccmDemandSignalItemsFilterArgs>> filters;

    public Optional<Output<List<GetInternalOccmDemandSignalItemsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The customer group ocid by which we would filter the list.
     * 
     */
    @Import(name="occCustomerGroupId", required=true)
    private Output<String> occCustomerGroupId;

    /**
     * @return The customer group ocid by which we would filter the list.
     * 
     */
    public Output<String> occCustomerGroupId() {
        return this.occCustomerGroupId;
    }

    /**
     * A query parameter to filter the list of demand signal items based on a demand signal id.
     * 
     */
    @Import(name="occmDemandSignalId")
    private @Nullable Output<String> occmDemandSignalId;

    /**
     * @return A query parameter to filter the list of demand signal items based on a demand signal id.
     * 
     */
    public Optional<Output<String>> occmDemandSignalId() {
        return Optional.ofNullable(this.occmDemandSignalId);
    }

    /**
     * A query parameter to filter the list of demand signal details based on the resource name.
     * 
     */
    @Import(name="resourceName")
    private @Nullable Output<String> resourceName;

    /**
     * @return A query parameter to filter the list of demand signal details based on the resource name.
     * 
     */
    public Optional<Output<String>> resourceName() {
        return Optional.ofNullable(this.resourceName);
    }

    private GetInternalOccmDemandSignalItemsArgs() {}

    private GetInternalOccmDemandSignalItemsArgs(GetInternalOccmDemandSignalItemsArgs $) {
        this.compartmentId = $.compartmentId;
        this.demandSignalNamespace = $.demandSignalNamespace;
        this.filters = $.filters;
        this.occCustomerGroupId = $.occCustomerGroupId;
        this.occmDemandSignalId = $.occmDemandSignalId;
        this.resourceName = $.resourceName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInternalOccmDemandSignalItemsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInternalOccmDemandSignalItemsArgs $;

        public Builder() {
            $ = new GetInternalOccmDemandSignalItemsArgs();
        }

        public Builder(GetInternalOccmDemandSignalItemsArgs defaults) {
            $ = new GetInternalOccmDemandSignalItemsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param demandSignalNamespace A query parameter to filter the list of demand signal details based on the namespace.
         * 
         * @return builder
         * 
         */
        public Builder demandSignalNamespace(@Nullable Output<String> demandSignalNamespace) {
            $.demandSignalNamespace = demandSignalNamespace;
            return this;
        }

        /**
         * @param demandSignalNamespace A query parameter to filter the list of demand signal details based on the namespace.
         * 
         * @return builder
         * 
         */
        public Builder demandSignalNamespace(String demandSignalNamespace) {
            return demandSignalNamespace(Output.of(demandSignalNamespace));
        }

        public Builder filters(@Nullable Output<List<GetInternalOccmDemandSignalItemsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetInternalOccmDemandSignalItemsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetInternalOccmDemandSignalItemsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param occCustomerGroupId The customer group ocid by which we would filter the list.
         * 
         * @return builder
         * 
         */
        public Builder occCustomerGroupId(Output<String> occCustomerGroupId) {
            $.occCustomerGroupId = occCustomerGroupId;
            return this;
        }

        /**
         * @param occCustomerGroupId The customer group ocid by which we would filter the list.
         * 
         * @return builder
         * 
         */
        public Builder occCustomerGroupId(String occCustomerGroupId) {
            return occCustomerGroupId(Output.of(occCustomerGroupId));
        }

        /**
         * @param occmDemandSignalId A query parameter to filter the list of demand signal items based on a demand signal id.
         * 
         * @return builder
         * 
         */
        public Builder occmDemandSignalId(@Nullable Output<String> occmDemandSignalId) {
            $.occmDemandSignalId = occmDemandSignalId;
            return this;
        }

        /**
         * @param occmDemandSignalId A query parameter to filter the list of demand signal items based on a demand signal id.
         * 
         * @return builder
         * 
         */
        public Builder occmDemandSignalId(String occmDemandSignalId) {
            return occmDemandSignalId(Output.of(occmDemandSignalId));
        }

        /**
         * @param resourceName A query parameter to filter the list of demand signal details based on the resource name.
         * 
         * @return builder
         * 
         */
        public Builder resourceName(@Nullable Output<String> resourceName) {
            $.resourceName = resourceName;
            return this;
        }

        /**
         * @param resourceName A query parameter to filter the list of demand signal details based on the resource name.
         * 
         * @return builder
         * 
         */
        public Builder resourceName(String resourceName) {
            return resourceName(Output.of(resourceName));
        }

        public GetInternalOccmDemandSignalItemsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetInternalOccmDemandSignalItemsArgs", "compartmentId");
            }
            if ($.occCustomerGroupId == null) {
                throw new MissingRequiredPropertyException("GetInternalOccmDemandSignalItemsArgs", "occCustomerGroupId");
            }
            return $;
        }
    }

}
