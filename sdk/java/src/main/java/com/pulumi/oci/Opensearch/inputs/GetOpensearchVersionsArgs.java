// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opensearch.inputs.GetOpensearchVersionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOpensearchVersionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOpensearchVersionsArgs Empty = new GetOpensearchVersionsArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetOpensearchVersionsFilterArgs>> filters;

    public Optional<Output<List<GetOpensearchVersionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetOpensearchVersionsArgs() {}

    private GetOpensearchVersionsArgs(GetOpensearchVersionsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOpensearchVersionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOpensearchVersionsArgs $;

        public Builder() {
            $ = new GetOpensearchVersionsArgs();
        }

        public Builder(GetOpensearchVersionsArgs defaults) {
            $ = new GetOpensearchVersionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetOpensearchVersionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetOpensearchVersionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetOpensearchVersionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetOpensearchVersionsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetOpensearchVersionsArgs", "compartmentId");
            }
            return $;
        }
    }

}
