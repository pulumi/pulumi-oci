// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Nosql.inputs.GetTablesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTablesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTablesArgs Empty = new GetTablesArgs();

    /**
     * The ID of a table&#39;s compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of a table&#39;s compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetTablesFilterArgs>> filters;

    public Optional<Output<List<GetTablesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A shell-globbing-style (*?[]) filter for names.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A shell-globbing-style (*?[]) filter for names.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Filter list by the lifecycle state of the item.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return Filter list by the lifecycle state of the item.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetTablesArgs() {}

    private GetTablesArgs(GetTablesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTablesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTablesArgs $;

        public Builder() {
            $ = new GetTablesArgs();
        }

        public Builder(GetTablesArgs defaults) {
            $ = new GetTablesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of a table&#39;s compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of a table&#39;s compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetTablesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetTablesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetTablesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A shell-globbing-style (*?[]) filter for names.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A shell-globbing-style (*?[]) filter for names.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state Filter list by the lifecycle state of the item.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state Filter list by the lifecycle state of the item.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetTablesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}