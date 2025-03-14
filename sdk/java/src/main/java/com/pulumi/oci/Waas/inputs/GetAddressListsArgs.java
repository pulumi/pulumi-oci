// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waas.inputs.GetAddressListsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAddressListsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAddressListsArgs Empty = new GetAddressListsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAddressListsFilterArgs>> filters;

    public Optional<Output<List<GetAddressListsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Filter address lists using a list of address lists OCIDs.
     * 
     */
    @Import(name="ids")
    private @Nullable Output<List<String>> ids;

    /**
     * @return Filter address lists using a list of address lists OCIDs.
     * 
     */
    public Optional<Output<List<String>>> ids() {
        return Optional.ofNullable(this.ids);
    }

    /**
     * Filter address lists using a list of names.
     * 
     */
    @Import(name="names")
    private @Nullable Output<List<String>> names;

    /**
     * @return Filter address lists using a list of names.
     * 
     */
    public Optional<Output<List<String>>> names() {
        return Optional.ofNullable(this.names);
    }

    /**
     * Filter address lists using a list of lifecycle states.
     * 
     */
    @Import(name="states")
    private @Nullable Output<List<String>> states;

    /**
     * @return Filter address lists using a list of lifecycle states.
     * 
     */
    public Optional<Output<List<String>>> states() {
        return Optional.ofNullable(this.states);
    }

    /**
     * A filter that matches address lists created on or after the specified date-time.
     * 
     */
    @Import(name="timeCreatedGreaterThanOrEqualTo")
    private @Nullable Output<String> timeCreatedGreaterThanOrEqualTo;

    /**
     * @return A filter that matches address lists created on or after the specified date-time.
     * 
     */
    public Optional<Output<String>> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }

    /**
     * A filter that matches address lists created before the specified date-time.
     * 
     */
    @Import(name="timeCreatedLessThan")
    private @Nullable Output<String> timeCreatedLessThan;

    /**
     * @return A filter that matches address lists created before the specified date-time.
     * 
     */
    public Optional<Output<String>> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    private GetAddressListsArgs() {}

    private GetAddressListsArgs(GetAddressListsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.ids = $.ids;
        this.names = $.names;
        this.states = $.states;
        this.timeCreatedGreaterThanOrEqualTo = $.timeCreatedGreaterThanOrEqualTo;
        this.timeCreatedLessThan = $.timeCreatedLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAddressListsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAddressListsArgs $;

        public Builder() {
            $ = new GetAddressListsArgs();
        }

        public Builder(GetAddressListsArgs defaults) {
            $ = new GetAddressListsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetAddressListsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAddressListsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAddressListsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param ids Filter address lists using a list of address lists OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(@Nullable Output<List<String>> ids) {
            $.ids = ids;
            return this;
        }

        /**
         * @param ids Filter address lists using a list of address lists OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(List<String> ids) {
            return ids(Output.of(ids));
        }

        /**
         * @param ids Filter address lists using a list of address lists OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(String... ids) {
            return ids(List.of(ids));
        }

        /**
         * @param names Filter address lists using a list of names.
         * 
         * @return builder
         * 
         */
        public Builder names(@Nullable Output<List<String>> names) {
            $.names = names;
            return this;
        }

        /**
         * @param names Filter address lists using a list of names.
         * 
         * @return builder
         * 
         */
        public Builder names(List<String> names) {
            return names(Output.of(names));
        }

        /**
         * @param names Filter address lists using a list of names.
         * 
         * @return builder
         * 
         */
        public Builder names(String... names) {
            return names(List.of(names));
        }

        /**
         * @param states Filter address lists using a list of lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder states(@Nullable Output<List<String>> states) {
            $.states = states;
            return this;
        }

        /**
         * @param states Filter address lists using a list of lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder states(List<String> states) {
            return states(Output.of(states));
        }

        /**
         * @param states Filter address lists using a list of lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder states(String... states) {
            return states(List.of(states));
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter that matches address lists created on or after the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable Output<String> timeCreatedGreaterThanOrEqualTo) {
            $.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter that matches address lists created on or after the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(String timeCreatedGreaterThanOrEqualTo) {
            return timeCreatedGreaterThanOrEqualTo(Output.of(timeCreatedGreaterThanOrEqualTo));
        }

        /**
         * @param timeCreatedLessThan A filter that matches address lists created before the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(@Nullable Output<String> timeCreatedLessThan) {
            $.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }

        /**
         * @param timeCreatedLessThan A filter that matches address lists created before the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(String timeCreatedLessThan) {
            return timeCreatedLessThan(Output.of(timeCreatedLessThan));
        }

        public GetAddressListsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAddressListsArgs", "compartmentId");
            }
            return $;
        }
    }

}
