// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.inputs.GetInternalNamespaceOccOverviewsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetInternalNamespaceOccOverviewsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInternalNamespaceOccOverviewsArgs Empty = new GetInternalNamespaceOccOverviewsArgs();

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

    @Import(name="filters")
    private @Nullable Output<List<GetInternalNamespaceOccOverviewsFilterArgs>> filters;

    public Optional<Output<List<GetInternalNamespaceOccOverviewsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
     * 
     */
    @Import(name="from")
    private @Nullable Output<String> from;

    /**
     * @return The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
     * 
     */
    public Optional<Output<String>> from() {
        return Optional.ofNullable(this.from);
    }

    /**
     * The namespace by which we would filter the list.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The namespace by which we would filter the list.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
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
     * The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
     * 
     */
    @Import(name="to")
    private @Nullable Output<String> to;

    /**
     * @return The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
     * 
     */
    public Optional<Output<String>> to() {
        return Optional.ofNullable(this.to);
    }

    /**
     * Workload type using the resources in an availability catalog can be filtered.
     * 
     */
    @Import(name="workloadType")
    private @Nullable Output<String> workloadType;

    /**
     * @return Workload type using the resources in an availability catalog can be filtered.
     * 
     */
    public Optional<Output<String>> workloadType() {
        return Optional.ofNullable(this.workloadType);
    }

    private GetInternalNamespaceOccOverviewsArgs() {}

    private GetInternalNamespaceOccOverviewsArgs(GetInternalNamespaceOccOverviewsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.from = $.from;
        this.namespace = $.namespace;
        this.occCustomerGroupId = $.occCustomerGroupId;
        this.to = $.to;
        this.workloadType = $.workloadType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInternalNamespaceOccOverviewsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInternalNamespaceOccOverviewsArgs $;

        public Builder() {
            $ = new GetInternalNamespaceOccOverviewsArgs();
        }

        public Builder(GetInternalNamespaceOccOverviewsArgs defaults) {
            $ = new GetInternalNamespaceOccOverviewsArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetInternalNamespaceOccOverviewsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetInternalNamespaceOccOverviewsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetInternalNamespaceOccOverviewsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param from The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
         * 
         * @return builder
         * 
         */
        public Builder from(@Nullable Output<String> from) {
            $.from = from;
            return this;
        }

        /**
         * @param from The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
         * 
         * @return builder
         * 
         */
        public Builder from(String from) {
            return from(Output.of(from));
        }

        /**
         * @param namespace The namespace by which we would filter the list.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The namespace by which we would filter the list.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
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
         * @param to The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
         * 
         * @return builder
         * 
         */
        public Builder to(@Nullable Output<String> to) {
            $.to = to;
            return this;
        }

        /**
         * @param to The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
         * 
         * @return builder
         * 
         */
        public Builder to(String to) {
            return to(Output.of(to));
        }

        /**
         * @param workloadType Workload type using the resources in an availability catalog can be filtered.
         * 
         * @return builder
         * 
         */
        public Builder workloadType(@Nullable Output<String> workloadType) {
            $.workloadType = workloadType;
            return this;
        }

        /**
         * @param workloadType Workload type using the resources in an availability catalog can be filtered.
         * 
         * @return builder
         * 
         */
        public Builder workloadType(String workloadType) {
            return workloadType(Output.of(workloadType));
        }

        public GetInternalNamespaceOccOverviewsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetInternalNamespaceOccOverviewsArgs", "compartmentId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetInternalNamespaceOccOverviewsArgs", "namespace");
            }
            if ($.occCustomerGroupId == null) {
                throw new MissingRequiredPropertyException("GetInternalNamespaceOccOverviewsArgs", "occCustomerGroupId");
            }
            return $;
        }
    }

}
