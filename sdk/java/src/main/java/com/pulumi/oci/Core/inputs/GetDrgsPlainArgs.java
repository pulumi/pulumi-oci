// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetDrgsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDrgsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrgsPlainArgs Empty = new GetDrgsPlainArgs();

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
    private @Nullable List<GetDrgsFilter> filters;

    public Optional<List<GetDrgsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDrgsPlainArgs() {}

    private GetDrgsPlainArgs(GetDrgsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDrgsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDrgsPlainArgs $;

        public Builder() {
            $ = new GetDrgsPlainArgs();
        }

        public Builder(GetDrgsPlainArgs defaults) {
            $ = new GetDrgsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetDrgsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDrgsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetDrgsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDrgsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
