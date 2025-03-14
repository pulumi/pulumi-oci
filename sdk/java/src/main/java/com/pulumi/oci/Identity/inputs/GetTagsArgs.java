// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.GetTagsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTagsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTagsArgs Empty = new GetTagsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetTagsFilterArgs>> filters;

    public Optional<Output<List<GetTagsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the tag namespace.
     * 
     */
    @Import(name="tagNamespaceId", required=true)
    private Output<String> tagNamespaceId;

    /**
     * @return The OCID of the tag namespace.
     * 
     */
    public Output<String> tagNamespaceId() {
        return this.tagNamespaceId;
    }

    private GetTagsArgs() {}

    private GetTagsArgs(GetTagsArgs $) {
        this.filters = $.filters;
        this.state = $.state;
        this.tagNamespaceId = $.tagNamespaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTagsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTagsArgs $;

        public Builder() {
            $ = new GetTagsArgs();
        }

        public Builder(GetTagsArgs defaults) {
            $ = new GetTagsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetTagsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetTagsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetTagsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param tagNamespaceId The OCID of the tag namespace.
         * 
         * @return builder
         * 
         */
        public Builder tagNamespaceId(Output<String> tagNamespaceId) {
            $.tagNamespaceId = tagNamespaceId;
            return this;
        }

        /**
         * @param tagNamespaceId The OCID of the tag namespace.
         * 
         * @return builder
         * 
         */
        public Builder tagNamespaceId(String tagNamespaceId) {
            return tagNamespaceId(Output.of(tagNamespaceId));
        }

        public GetTagsArgs build() {
            if ($.tagNamespaceId == null) {
                throw new MissingRequiredPropertyException("GetTagsArgs", "tagNamespaceId");
            }
            return $;
        }
    }

}
