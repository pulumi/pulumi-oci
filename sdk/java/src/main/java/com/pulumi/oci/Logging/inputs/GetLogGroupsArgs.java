// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Logging.inputs.GetLogGroupsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLogGroupsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLogGroupsArgs Empty = new GetLogGroupsArgs();

    /**
     * Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Resource name
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return Resource name
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetLogGroupsFilterArgs>> filters;

    public Optional<Output<List<GetLogGroupsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Specifies whether or not nested compartments should be traversed. Defaults to false.
     * 
     */
    @Import(name="isCompartmentIdInSubtree")
    private @Nullable Output<Boolean> isCompartmentIdInSubtree;

    /**
     * @return Specifies whether or not nested compartments should be traversed. Defaults to false.
     * 
     */
    public Optional<Output<Boolean>> isCompartmentIdInSubtree() {
        return Optional.ofNullable(this.isCompartmentIdInSubtree);
    }

    private GetLogGroupsArgs() {}

    private GetLogGroupsArgs(GetLogGroupsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isCompartmentIdInSubtree = $.isCompartmentIdInSubtree;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLogGroupsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLogGroupsArgs $;

        public Builder() {
            $ = new GetLogGroupsArgs();
        }

        public Builder(GetLogGroupsArgs defaults) {
            $ = new GetLogGroupsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName Resource name
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName Resource name
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetLogGroupsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetLogGroupsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetLogGroupsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isCompartmentIdInSubtree Specifies whether or not nested compartments should be traversed. Defaults to false.
         * 
         * @return builder
         * 
         */
        public Builder isCompartmentIdInSubtree(@Nullable Output<Boolean> isCompartmentIdInSubtree) {
            $.isCompartmentIdInSubtree = isCompartmentIdInSubtree;
            return this;
        }

        /**
         * @param isCompartmentIdInSubtree Specifies whether or not nested compartments should be traversed. Defaults to false.
         * 
         * @return builder
         * 
         */
        public Builder isCompartmentIdInSubtree(Boolean isCompartmentIdInSubtree) {
            return isCompartmentIdInSubtree(Output.of(isCompartmentIdInSubtree));
        }

        public GetLogGroupsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}