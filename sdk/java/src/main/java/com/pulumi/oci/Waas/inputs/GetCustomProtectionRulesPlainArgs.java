// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Waas.inputs.GetCustomProtectionRulesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCustomProtectionRulesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCustomProtectionRulesPlainArgs Empty = new GetCustomProtectionRulesPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Filter custom protection rules using a list of display names.
     * 
     */
    @Import(name="displayNames")
    private @Nullable List<String> displayNames;

    /**
     * @return Filter custom protection rules using a list of display names.
     * 
     */
    public Optional<List<String>> displayNames() {
        return Optional.ofNullable(this.displayNames);
    }

    @Import(name="filters")
    private @Nullable List<GetCustomProtectionRulesFilter> filters;

    public Optional<List<GetCustomProtectionRulesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Filter custom protection rules using a list of custom protection rule OCIDs.
     * 
     */
    @Import(name="ids")
    private @Nullable List<String> ids;

    /**
     * @return Filter custom protection rules using a list of custom protection rule OCIDs.
     * 
     */
    public Optional<List<String>> ids() {
        return Optional.ofNullable(this.ids);
    }

    /**
     * Filter Custom Protection rules using a list of lifecycle states.
     * 
     */
    @Import(name="states")
    private @Nullable List<String> states;

    /**
     * @return Filter Custom Protection rules using a list of lifecycle states.
     * 
     */
    public Optional<List<String>> states() {
        return Optional.ofNullable(this.states);
    }

    /**
     * A filter that matches Custom Protection rules created on or after the specified date-time.
     * 
     */
    @Import(name="timeCreatedGreaterThanOrEqualTo")
    private @Nullable String timeCreatedGreaterThanOrEqualTo;

    /**
     * @return A filter that matches Custom Protection rules created on or after the specified date-time.
     * 
     */
    public Optional<String> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }

    /**
     * A filter that matches custom protection rules created before the specified date-time.
     * 
     */
    @Import(name="timeCreatedLessThan")
    private @Nullable String timeCreatedLessThan;

    /**
     * @return A filter that matches custom protection rules created before the specified date-time.
     * 
     */
    public Optional<String> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    private GetCustomProtectionRulesPlainArgs() {}

    private GetCustomProtectionRulesPlainArgs(GetCustomProtectionRulesPlainArgs $) {
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
    public static Builder builder(GetCustomProtectionRulesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCustomProtectionRulesPlainArgs $;

        public Builder() {
            $ = new GetCustomProtectionRulesPlainArgs();
        }

        public Builder(GetCustomProtectionRulesPlainArgs defaults) {
            $ = new GetCustomProtectionRulesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayNames Filter custom protection rules using a list of display names.
         * 
         * @return builder
         * 
         */
        public Builder displayNames(@Nullable List<String> displayNames) {
            $.displayNames = displayNames;
            return this;
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

        public Builder filters(@Nullable List<GetCustomProtectionRulesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetCustomProtectionRulesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param ids Filter custom protection rules using a list of custom protection rule OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder ids(@Nullable List<String> ids) {
            $.ids = ids;
            return this;
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
        public Builder states(@Nullable List<String> states) {
            $.states = states;
            return this;
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
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable String timeCreatedGreaterThanOrEqualTo) {
            $.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeCreatedLessThan A filter that matches custom protection rules created before the specified date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(@Nullable String timeCreatedLessThan) {
            $.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }

        public GetCustomProtectionRulesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}