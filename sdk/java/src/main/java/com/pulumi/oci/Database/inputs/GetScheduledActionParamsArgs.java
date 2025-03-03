// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetScheduledActionParamsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetScheduledActionParamsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetScheduledActionParamsArgs Empty = new GetScheduledActionParamsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetScheduledActionParamsFilterArgs>> filters;

    public Optional<Output<List<GetScheduledActionParamsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The type of the scheduled action
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return The type of the scheduled action
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private GetScheduledActionParamsArgs() {}

    private GetScheduledActionParamsArgs(GetScheduledActionParamsArgs $) {
        this.filters = $.filters;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetScheduledActionParamsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetScheduledActionParamsArgs $;

        public Builder() {
            $ = new GetScheduledActionParamsArgs();
        }

        public Builder(GetScheduledActionParamsArgs defaults) {
            $ = new GetScheduledActionParamsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetScheduledActionParamsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetScheduledActionParamsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetScheduledActionParamsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param type The type of the scheduled action
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of the scheduled action
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GetScheduledActionParamsArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("GetScheduledActionParamsArgs", "type");
            }
            return $;
        }
    }

}
