// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Opensearch.inputs.GetOpensearchVersionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOpensearchVersionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOpensearchVersionsPlainArgs Empty = new GetOpensearchVersionsPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetOpensearchVersionsFilter> filters;

    public Optional<List<GetOpensearchVersionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetOpensearchVersionsPlainArgs() {}

    private GetOpensearchVersionsPlainArgs(GetOpensearchVersionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOpensearchVersionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOpensearchVersionsPlainArgs $;

        public Builder() {
            $ = new GetOpensearchVersionsPlainArgs();
        }

        public Builder(GetOpensearchVersionsPlainArgs defaults) {
            $ = new GetOpensearchVersionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetOpensearchVersionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetOpensearchVersionsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetOpensearchVersionsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}