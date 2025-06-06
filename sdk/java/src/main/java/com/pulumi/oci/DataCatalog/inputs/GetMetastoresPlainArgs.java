// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataCatalog.inputs.GetMetastoresFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMetastoresPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMetastoresPlainArgs Empty = new GetMetastoresPlainArgs();

    /**
     * The OCID of the compartment where you want to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment where you want to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetMetastoresFilter> filters;

    public Optional<List<GetMetastoresFilter>> filters() {
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

    private GetMetastoresPlainArgs() {}

    private GetMetastoresPlainArgs(GetMetastoresPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMetastoresPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMetastoresPlainArgs $;

        public Builder() {
            $ = new GetMetastoresPlainArgs();
        }

        public Builder(GetMetastoresPlainArgs defaults) {
            $ = new GetMetastoresPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment where you want to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given. The match is not case sensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetMetastoresFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMetastoresFilter... filters) {
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

        public GetMetastoresPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetMetastoresPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
