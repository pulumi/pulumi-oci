// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Waas.inputs.GetCustomProtectionRulesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCustomProtectionRulesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCustomProtectionRulesArgs Empty = new GetCustomProtectionRulesArgs();

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

    /**
     * Filter custom protection rules using a list of display names.
     * 
     */
    @Import(name="displayNames")
    private @Nullable Output<List<String>> displayNames;

    /**
     * @return Filter custom protection rules using a list of display names.
     * 
     */
    public Optional<Output<List<String>>> displayNames() {
        return Optional.ofNullable(this.displayNames);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetCustomProtectionRulesFilterArgs>> filters;

    public Optional<Output<List<GetCustomProtectionRulesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Filter custom protection rules using a list of custom protection rule OCIDs.
     * 
     */
    @Import(name="ids")
    private @Nullable Output<List<String>> ids;

    /**
     * @return Filter custom protection rules using a list of custom protection rule OCIDs.
     * 
     */
    public Optional<Output<List<String>>> ids() {
        return Optional.ofNullable(this.ids);
    }

    /**
     * Filter Custom Protection rules using a list of lifecycle states.
     * 
     */
    @Import(name="states")
    private @Nullable Output<List<String>> states;

    /**
     * @return Filter Custom Protection rules using a list of lifecycle states.
     * 
     */
    public Optional<Output<List<String>>> states() {
        return Optional.ofNullable(this.states);
    }

    /**
     * A filter that matches Custom Protection rules created on or after the specified date-time.
     * 
     */
    @Import(name="timeCreatedGreaterThanOrEqualTo")
    private @Nullable Output<String> timeCreatedGreaterThanOrEqualTo;

    /**
     * @return A filter that matches Custom Protection rules created on or after the specified date-time.
     * 
     */
    public Optional<Output<String>> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }

    /**
     * A filter that matches custom protection rules created before the specified date-time.
     * 
     */
    @Import(name="timeCreatedLessThan")
    private @Nullable Output<String> timeCreatedLessThan;

    /**
     * @return A filter that matches custom protection rules created before the specified date-time.
     * 
     */
    public Optional<Output<String>> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    private GetCustomProtectionRulesArgs() {}

    private GetCustomProtectionRulesArgs(GetCustomProtectionRulesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayNames = $.displayNames;
        this.filters = $.filters;
        this.ids = $.ids;
        this.states = $.states;
        this.timeCreatedGreaterThanOrEqualTo = $.timeCreatedGreaterThanOrEqualTo;
        this.timeCreatedLessThan = $.timeCreatedLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCustomProtectionRulesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCustomProtectionRulesArgs $;

        public Builder() {
            $ = new GetCustomProtectionRulesArgs();
        }

        public Builder(GetCustomProtectionRulesArgs defaults) {
            $ = new GetCustomProtectionRulesArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param displayNames Filter custom protection rules using a list of display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(@Nullable Output<List<String>> displayNames) {
            $.displayNames = displayNames;
            return this;
        }

        /**
         * @param displayNames Filter custom protection rules using a list of display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(List<String> displayNames) {
            return displayNames(Output.of(displayNames));
        }

        /**
         * @param displayNames Filter custom protection rules using a list of display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(String... displayNames) {
            return displayNames(List.of(displayNames));
        }

        public Builder filters(@Nullable Output<List<GetCustomProtectionRulesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetCustomProtectionRulesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetCustomProtectionRulesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param ids Filter custom protection rules using a list of custom protection rule OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(@Nullable Output<List<String>> ids) {
            $.ids = ids;
            return this;
        }

        /**
         * @param ids Filter custom protection rules using a list of custom protection rule OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(List<String> ids) {
            return ids(Output.of(ids));
        }

        /**
         * @param ids Filter custom protection rules using a list of custom protection rule OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(String... ids) {
            return ids(List.of(ids));
        }

        /**
         * @param states Filter Custom Protection rules using a list of lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder states(@Nullable Output<List<String>> states) {
            $.states = states;
            return this;
        }

        /**
         * @param states Filter Custom Protection rules using a list of lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder states(List<String> states) {
            return states(Output.of(states));
        }

        /**
         * @param states Filter Custom Protection rules using a list of lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder states(String... states) {
            return states(List.of(states));
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter that matches Custom Protection rules created on or after the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable Output<String> timeCreatedGreaterThanOrEqualTo) {
            $.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter that matches Custom Protection rules created on or after the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(String timeCreatedGreaterThanOrEqualTo) {
            return timeCreatedGreaterThanOrEqualTo(Output.of(timeCreatedGreaterThanOrEqualTo));
        }

        /**
         * @param timeCreatedLessThan A filter that matches custom protection rules created before the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(@Nullable Output<String> timeCreatedLessThan) {
            $.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }

        /**
         * @param timeCreatedLessThan A filter that matches custom protection rules created before the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(String timeCreatedLessThan) {
            return timeCreatedLessThan(Output.of(timeCreatedLessThan));
        }

        public GetCustomProtectionRulesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}