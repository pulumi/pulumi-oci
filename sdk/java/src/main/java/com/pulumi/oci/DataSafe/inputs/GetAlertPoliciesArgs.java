// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetAlertPoliciesFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAlertPoliciesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAlertPoliciesArgs Empty = new GetAlertPoliciesArgs();

    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    @Import(name="accessLevel")
    private @Nullable Output<String> accessLevel;

    /**
     * @return Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    public Optional<Output<String>> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }

    /**
     * A filter to return policy by it&#39;s OCID.
     * 
     */
    @Import(name="alertPolicyId")
    private @Nullable Output<String> alertPolicyId;

    /**
     * @return A filter to return policy by it&#39;s OCID.
     * 
     */
    public Optional<Output<String>> alertPolicyId() {
        return Optional.ofNullable(this.alertPolicyId);
    }

    /**
     * A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * A filter to return only resources that match the specified display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAlertPoliciesFilterArgs>> filters;

    public Optional<Output<List<GetAlertPoliciesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * An optional filter to return only alert policies that are user-defined or not.
     * 
     */
    @Import(name="isUserDefined")
    private @Nullable Output<Boolean> isUserDefined;

    /**
     * @return An optional filter to return only alert policies that are user-defined or not.
     * 
     */
    public Optional<Output<Boolean>> isUserDefined() {
        return Optional.ofNullable(this.isUserDefined);
    }

    /**
     * An optional filter to return only alert policies that have the given life-cycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return An optional filter to return only alert policies that have the given life-cycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    @Import(name="timeCreatedGreaterThanOrEqualTo")
    private @Nullable Output<String> timeCreatedGreaterThanOrEqualTo;

    /**
     * @return A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    public Optional<Output<String>> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    @Import(name="timeCreatedLessThan")
    private @Nullable Output<String> timeCreatedLessThan;

    /**
     * @return Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    public Optional<Output<String>> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    /**
     * An optional filter to return only alert policies of a certain type.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return An optional filter to return only alert policies of a certain type.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private GetAlertPoliciesArgs() {}

    private GetAlertPoliciesArgs(GetAlertPoliciesArgs $) {
        this.accessLevel = $.accessLevel;
        this.alertPolicyId = $.alertPolicyId;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isUserDefined = $.isUserDefined;
        this.state = $.state;
        this.timeCreatedGreaterThanOrEqualTo = $.timeCreatedGreaterThanOrEqualTo;
        this.timeCreatedLessThan = $.timeCreatedLessThan;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAlertPoliciesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAlertPoliciesArgs $;

        public Builder() {
            $ = new GetAlertPoliciesArgs();
        }

        public Builder(GetAlertPoliciesArgs defaults) {
            $ = new GetAlertPoliciesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(@Nullable Output<String> accessLevel) {
            $.accessLevel = accessLevel;
            return this;
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(String accessLevel) {
            return accessLevel(Output.of(accessLevel));
        }

        /**
         * @param alertPolicyId A filter to return policy by it&#39;s OCID.
         * 
         * @return builder
         * 
         */
        public Builder alertPolicyId(@Nullable Output<String> alertPolicyId) {
            $.alertPolicyId = alertPolicyId;
            return this;
        }

        /**
         * @param alertPolicyId A filter to return policy by it&#39;s OCID.
         * 
         * @return builder
         * 
         */
        public Builder alertPolicyId(String alertPolicyId) {
            return alertPolicyId(Output.of(alertPolicyId));
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAlertPoliciesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAlertPoliciesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAlertPoliciesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isUserDefined An optional filter to return only alert policies that are user-defined or not.
         * 
         * @return builder
         * 
         */
        public Builder isUserDefined(@Nullable Output<Boolean> isUserDefined) {
            $.isUserDefined = isUserDefined;
            return this;
        }

        /**
         * @param isUserDefined An optional filter to return only alert policies that are user-defined or not.
         * 
         * @return builder
         * 
         */
        public Builder isUserDefined(Boolean isUserDefined) {
            return isUserDefined(Output.of(isUserDefined));
        }

        /**
         * @param state An optional filter to return only alert policies that have the given life-cycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state An optional filter to return only alert policies that have the given life-cycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable Output<String> timeCreatedGreaterThanOrEqualTo) {
            $.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(String timeCreatedGreaterThanOrEqualTo) {
            return timeCreatedGreaterThanOrEqualTo(Output.of(timeCreatedGreaterThanOrEqualTo));
        }

        /**
         * @param timeCreatedLessThan Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(@Nullable Output<String> timeCreatedLessThan) {
            $.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }

        /**
         * @param timeCreatedLessThan Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(String timeCreatedLessThan) {
            return timeCreatedLessThan(Output.of(timeCreatedLessThan));
        }

        /**
         * @param type An optional filter to return only alert policies of a certain type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type An optional filter to return only alert policies of a certain type.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GetAlertPoliciesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAlertPoliciesArgs", "compartmentId");
            }
            return $;
        }
    }

}
