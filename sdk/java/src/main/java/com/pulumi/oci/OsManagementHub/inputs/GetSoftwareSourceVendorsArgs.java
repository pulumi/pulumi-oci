// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.inputs.GetSoftwareSourceVendorsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSoftwareSourceVendorsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwareSourceVendorsArgs Empty = new GetSoftwareSourceVendorsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetSoftwareSourceVendorsFilterArgs>> filters;

    public Optional<Output<List<GetSoftwareSourceVendorsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The name of the entity to be queried.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the entity to be queried.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private GetSoftwareSourceVendorsArgs() {}

    private GetSoftwareSourceVendorsArgs(GetSoftwareSourceVendorsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwareSourceVendorsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwareSourceVendorsArgs $;

        public Builder() {
            $ = new GetSoftwareSourceVendorsArgs();
        }

        public Builder(GetSoftwareSourceVendorsArgs defaults) {
            $ = new GetSoftwareSourceVendorsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetSoftwareSourceVendorsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSoftwareSourceVendorsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSoftwareSourceVendorsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name The name of the entity to be queried.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the entity to be queried.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetSoftwareSourceVendorsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetSoftwareSourceVendorsArgs", "compartmentId");
            }
            return $;
        }
    }

}
