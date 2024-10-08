// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.inputs.GetProcessSetsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProcessSetsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProcessSetsArgs Empty = new GetProcessSetsArgs();

    /**
     * The ID of the compartment in which data is listed.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which data is listed.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetProcessSetsFilterArgs>> filters;

    public Optional<Output<List<GetProcessSetsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetProcessSetsArgs() {}

    private GetProcessSetsArgs(GetProcessSetsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProcessSetsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProcessSetsArgs $;

        public Builder() {
            $ = new GetProcessSetsArgs();
        }

        public Builder(GetProcessSetsArgs defaults) {
            $ = new GetProcessSetsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetProcessSetsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetProcessSetsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetProcessSetsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetProcessSetsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetProcessSetsArgs", "compartmentId");
            }
            return $;
        }
    }

}
