// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Email.inputs.GetEmailDomainsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetEmailDomainsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEmailDomainsArgs Empty = new GetEmailDomainsArgs();

    /**
     * The OCID for the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID for the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetEmailDomainsFilterArgs>> filters;

    public Optional<Output<List<GetEmailDomainsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to only return resources that match the given id exactly.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return A filter to only return resources that match the given id exactly.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to only return resources that match the given name exactly.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Filter returned list by specified lifecycle state. This parameter is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return Filter returned list by specified lifecycle state. This parameter is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetEmailDomainsArgs() {}

    private GetEmailDomainsArgs(GetEmailDomainsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.id = $.id;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEmailDomainsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEmailDomainsArgs $;

        public Builder() {
            $ = new GetEmailDomainsArgs();
        }

        public Builder(GetEmailDomainsArgs defaults) {
            $ = new GetEmailDomainsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID for the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID for the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetEmailDomainsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetEmailDomainsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetEmailDomainsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id A filter to only return resources that match the given id exactly.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id A filter to only return resources that match the given id exactly.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param name A filter to only return resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to only return resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state Filter returned list by specified lifecycle state. This parameter is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state Filter returned list by specified lifecycle state. This parameter is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetEmailDomainsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetEmailDomainsArgs", "compartmentId");
            }
            return $;
        }
    }

}
