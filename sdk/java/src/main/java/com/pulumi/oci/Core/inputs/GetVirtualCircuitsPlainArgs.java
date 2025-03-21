// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetVirtualCircuitsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVirtualCircuitsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualCircuitsPlainArgs Empty = new GetVirtualCircuitsPlainArgs();

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

    /**
     * A filter to return only resources that match the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetVirtualCircuitsFilter> filters;

    public Optional<List<GetVirtualCircuitsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetVirtualCircuitsPlainArgs() {}

    private GetVirtualCircuitsPlainArgs(GetVirtualCircuitsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualCircuitsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualCircuitsPlainArgs $;

        public Builder() {
            $ = new GetVirtualCircuitsPlainArgs();
        }

        public Builder(GetVirtualCircuitsPlainArgs defaults) {
            $ = new GetVirtualCircuitsPlainArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetVirtualCircuitsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetVirtualCircuitsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetVirtualCircuitsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetVirtualCircuitsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
