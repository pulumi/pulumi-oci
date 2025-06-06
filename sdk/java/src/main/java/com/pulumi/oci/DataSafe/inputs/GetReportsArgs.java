// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetReportsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetReportsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReportsArgs Empty = new GetReportsArgs();

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
     * The name of the report definition to query.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The name of the report definition to query.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetReportsFilterArgs>> filters;

    public Optional<Output<List<GetReportsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * An optional filter to return only resources that match the specified mime type.
     * 
     */
    @Import(name="mimeType")
    private @Nullable Output<String> mimeType;

    /**
     * @return An optional filter to return only resources that match the specified mime type.
     * 
     */
    public Optional<Output<String>> mimeType() {
        return Optional.ofNullable(this.mimeType);
    }

    /**
     * The ID of the report definition to filter the list of reports
     * 
     */
    @Import(name="reportDefinitionId")
    private @Nullable Output<String> reportDefinitionId;

    /**
     * @return The ID of the report definition to filter the list of reports
     * 
     */
    public Optional<Output<String>> reportDefinitionId() {
        return Optional.ofNullable(this.reportDefinitionId);
    }

    /**
     * An optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return An optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only the resources that were generated after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeGeneratedGreaterThanOrEqualToQueryParam parameter retrieves all resources generated after that date.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    @Import(name="timeGeneratedGreaterThanOrEqualTo")
    private @Nullable Output<String> timeGeneratedGreaterThanOrEqualTo;

    /**
     * @return A filter to return only the resources that were generated after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeGeneratedGreaterThanOrEqualToQueryParam parameter retrieves all resources generated after that date.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    public Optional<Output<String>> timeGeneratedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGeneratedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were generated before a specific date. Specifying this parameter corresponding `timeGeneratedLessThan` parameter will retrieve all resources generated before the specified generated date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    @Import(name="timeGeneratedLessThan")
    private @Nullable Output<String> timeGeneratedLessThan;

    /**
     * @return Search for resources that were generated before a specific date. Specifying this parameter corresponding `timeGeneratedLessThan` parameter will retrieve all resources generated before the specified generated date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    public Optional<Output<String>> timeGeneratedLessThan() {
        return Optional.ofNullable(this.timeGeneratedLessThan);
    }

    /**
     * An optional filter to return only resources that match the specified type.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return An optional filter to return only resources that match the specified type.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private GetReportsArgs() {}

    private GetReportsArgs(GetReportsArgs $) {
        this.accessLevel = $.accessLevel;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.mimeType = $.mimeType;
        this.reportDefinitionId = $.reportDefinitionId;
        this.state = $.state;
        this.timeGeneratedGreaterThanOrEqualTo = $.timeGeneratedGreaterThanOrEqualTo;
        this.timeGeneratedLessThan = $.timeGeneratedLessThan;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetReportsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReportsArgs $;

        public Builder() {
            $ = new GetReportsArgs();
        }

        public Builder(GetReportsArgs defaults) {
            $ = new GetReportsArgs(Objects.requireNonNull(defaults));
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
         * @param displayName The name of the report definition to query.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The name of the report definition to query.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetReportsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetReportsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetReportsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param mimeType An optional filter to return only resources that match the specified mime type.
         * 
         * @return builder
         * 
         */
        public Builder mimeType(@Nullable Output<String> mimeType) {
            $.mimeType = mimeType;
            return this;
        }

        /**
         * @param mimeType An optional filter to return only resources that match the specified mime type.
         * 
         * @return builder
         * 
         */
        public Builder mimeType(String mimeType) {
            return mimeType(Output.of(mimeType));
        }

        /**
         * @param reportDefinitionId The ID of the report definition to filter the list of reports
         * 
         * @return builder
         * 
         */
        public Builder reportDefinitionId(@Nullable Output<String> reportDefinitionId) {
            $.reportDefinitionId = reportDefinitionId;
            return this;
        }

        /**
         * @param reportDefinitionId The ID of the report definition to filter the list of reports
         * 
         * @return builder
         * 
         */
        public Builder reportDefinitionId(String reportDefinitionId) {
            return reportDefinitionId(Output.of(reportDefinitionId));
        }

        /**
         * @param state An optional filter to return only resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state An optional filter to return only resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeGeneratedGreaterThanOrEqualTo A filter to return only the resources that were generated after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeGeneratedGreaterThanOrEqualToQueryParam parameter retrieves all resources generated after that date.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeGeneratedGreaterThanOrEqualTo(@Nullable Output<String> timeGeneratedGreaterThanOrEqualTo) {
            $.timeGeneratedGreaterThanOrEqualTo = timeGeneratedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeGeneratedGreaterThanOrEqualTo A filter to return only the resources that were generated after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeGeneratedGreaterThanOrEqualToQueryParam parameter retrieves all resources generated after that date.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeGeneratedGreaterThanOrEqualTo(String timeGeneratedGreaterThanOrEqualTo) {
            return timeGeneratedGreaterThanOrEqualTo(Output.of(timeGeneratedGreaterThanOrEqualTo));
        }

        /**
         * @param timeGeneratedLessThan Search for resources that were generated before a specific date. Specifying this parameter corresponding `timeGeneratedLessThan` parameter will retrieve all resources generated before the specified generated date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeGeneratedLessThan(@Nullable Output<String> timeGeneratedLessThan) {
            $.timeGeneratedLessThan = timeGeneratedLessThan;
            return this;
        }

        /**
         * @param timeGeneratedLessThan Search for resources that were generated before a specific date. Specifying this parameter corresponding `timeGeneratedLessThan` parameter will retrieve all resources generated before the specified generated date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * **Example:** 2016-12-19T16:39:57.600Z
         * 
         * @return builder
         * 
         */
        public Builder timeGeneratedLessThan(String timeGeneratedLessThan) {
            return timeGeneratedLessThan(Output.of(timeGeneratedLessThan));
        }

        /**
         * @param type An optional filter to return only resources that match the specified type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type An optional filter to return only resources that match the specified type.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GetReportsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetReportsArgs", "compartmentId");
            }
            return $;
        }
    }

}
