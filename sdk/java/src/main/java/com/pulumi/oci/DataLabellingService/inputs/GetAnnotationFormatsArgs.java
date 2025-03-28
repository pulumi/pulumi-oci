// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataLabellingService.inputs.GetAnnotationFormatsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAnnotationFormatsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAnnotationFormatsArgs Empty = new GetAnnotationFormatsArgs();

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
    private @Nullable Output<List<GetAnnotationFormatsFilterArgs>> filters;

    public Optional<Output<List<GetAnnotationFormatsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetAnnotationFormatsArgs() {}

    private GetAnnotationFormatsArgs(GetAnnotationFormatsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAnnotationFormatsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAnnotationFormatsArgs $;

        public Builder() {
            $ = new GetAnnotationFormatsArgs();
        }

        public Builder(GetAnnotationFormatsArgs defaults) {
            $ = new GetAnnotationFormatsArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetAnnotationFormatsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAnnotationFormatsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAnnotationFormatsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetAnnotationFormatsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAnnotationFormatsArgs", "compartmentId");
            }
            return $;
        }
    }

}
