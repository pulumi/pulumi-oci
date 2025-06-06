// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetServiceGatewaysFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetServiceGatewaysPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetServiceGatewaysPlainArgs Empty = new GetServiceGatewaysPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetServiceGatewaysFilter> filters;

    public Optional<List<GetServiceGatewaysFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    @Import(name="vcnId")
    private @Nullable String vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    public Optional<String> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private GetServiceGatewaysPlainArgs() {}

    private GetServiceGatewaysPlainArgs(GetServiceGatewaysPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.state = $.state;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetServiceGatewaysPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetServiceGatewaysPlainArgs $;

        public Builder() {
            $ = new GetServiceGatewaysPlainArgs();
        }

        public Builder(GetServiceGatewaysPlainArgs defaults) {
            $ = new GetServiceGatewaysPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetServiceGatewaysFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetServiceGatewaysFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable String vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        public GetServiceGatewaysPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetServiceGatewaysPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
