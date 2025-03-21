// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waf.inputs.GetWebAppFirewallPoliciesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetWebAppFirewallPoliciesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWebAppFirewallPoliciesPlainArgs Empty = new GetWebAppFirewallPoliciesPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetWebAppFirewallPoliciesFilter> filters;

    public Optional<List<GetWebAppFirewallPoliciesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only the WebAppFirewallPolicy with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return A filter to return only the WebAppFirewallPolicy with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the given lifecycleState.
     * 
     */
    @Import(name="states")
    private @Nullable List<String> states;

    /**
     * @return A filter to return only resources that match the given lifecycleState.
     * 
     */
    public Optional<List<String>> states() {
        return Optional.ofNullable(this.states);
    }

    private GetWebAppFirewallPoliciesPlainArgs() {}

    private GetWebAppFirewallPoliciesPlainArgs(GetWebAppFirewallPoliciesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.states = $.states;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWebAppFirewallPoliciesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWebAppFirewallPoliciesPlainArgs $;

        public Builder() {
            $ = new GetWebAppFirewallPoliciesPlainArgs();
        }

        public Builder(GetWebAppFirewallPoliciesPlainArgs defaults) {
            $ = new GetWebAppFirewallPoliciesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetWebAppFirewallPoliciesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetWebAppFirewallPoliciesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id A filter to return only the WebAppFirewallPolicy with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param states A filter to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder states(@Nullable List<String> states) {
            $.states = states;
            return this;
        }

        /**
         * @param states A filter to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder states(String... states) {
            return states(List.of(states));
        }

        public GetWebAppFirewallPoliciesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetWebAppFirewallPoliciesPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
