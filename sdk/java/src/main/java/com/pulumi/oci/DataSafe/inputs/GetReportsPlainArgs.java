// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetReportsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetReportsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReportsPlainArgs Empty = new GetReportsPlainArgs();

    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    @Import(name="accessLevel")
    private @Nullable String accessLevel;

    /**
     * @return Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }

    /**
     * A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Boolean compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * The name of the report definition to query.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return The name of the report definition to query.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetReportsFilter> filters;

    public Optional<List<GetReportsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * An optional filter to return only resources that match the specified mime type.
     * 
     */
    @Import(name="mimeType")
    private @Nullable String mimeType;

    /**
     * @return An optional filter to return only resources that match the specified mime type.
     * 
     */
    public Optional<String> mimeType() {
        return Optional.ofNullable(this.mimeType);
    }

    /**
     * The ID of the report definition to filter the list of reports
     * 
     */
    @Import(name="reportDefinitionId")
    private @Nullable String reportDefinitionId;

    /**
     * @return The ID of the report definition to filter the list of reports
     * 
     */
    public Optional<String> reportDefinitionId() {
        return Optional.ofNullable(this.reportDefinitionId);
    }

    /**
     * An optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return An optional filter to return only resources that match the specified lifecycle state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only the resources that were generated after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeGeneratedGreaterThanOrEqualToQueryParam parameter retrieves all resources generated after that date.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    @Import(name="timeGeneratedGreaterThanOrEqualTo")
    private @Nullable String timeGeneratedGreaterThanOrEqualTo;

    /**
     * @return A filter to return only the resources that were generated after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeGeneratedGreaterThanOrEqualToQueryParam parameter retrieves all resources generated after that date.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    public Optional<String> timeGeneratedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGeneratedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were generated before a specific date. Specifying this parameter corresponding `timeGeneratedLessThan` parameter will retrieve all resources generated before the specified generated date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    @Import(name="timeGeneratedLessThan")
    private @Nullable String timeGeneratedLessThan;

    /**
     * @return Search for resources that were generated before a specific date. Specifying this parameter corresponding `timeGeneratedLessThan` parameter will retrieve all resources generated before the specified generated date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     * **Example:** 2016-12-19T16:39:57.600Z
     * 
     */
    public Optional<String> timeGeneratedLessThan() {
        return Optional.ofNullable(this.timeGeneratedLessThan);
    }

    /**
     * An optional filter to return only resources that match the specified type.
     * 
     */
    @Import(name="type")
    private @Nullable String type;

    /**
     * @return An optional filter to return only resources that match the specified type.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    private GetReportsPlainArgs() {}

    private GetReportsPlainArgs(GetReportsPlainArgs $) {
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
    public static Builder builder(GetReportsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReportsPlainArgs $;

        public Builder() {
            $ = new GetReportsPlainArgs();
        }

        public Builder(GetReportsPlainArgs defaults) {
            $ = new GetReportsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(@Nullable String accessLevel) {
            $.accessLevel = accessLevel;
            return this;
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param displayName The name of the report definition to query.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetReportsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetReportsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param mimeType An optional filter to return only resources that match the specified mime type.
         * 
         * @return builder
         * 
         */
        public Builder mimeType(@Nullable String mimeType) {
            $.mimeType = mimeType;
            return this;
        }

        /**
         * @param reportDefinitionId The ID of the report definition to filter the list of reports
         * 
         * @return builder
         * 
         */
        public Builder reportDefinitionId(@Nullable String reportDefinitionId) {
            $.reportDefinitionId = reportDefinitionId;
            return this;
        }

        /**
         * @param state An optional filter to return only resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
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
        public Builder timeGeneratedGreaterThanOrEqualTo(@Nullable String timeGeneratedGreaterThanOrEqualTo) {
            $.timeGeneratedGreaterThanOrEqualTo = timeGeneratedGreaterThanOrEqualTo;
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
        public Builder timeGeneratedLessThan(@Nullable String timeGeneratedLessThan) {
            $.timeGeneratedLessThan = timeGeneratedLessThan;
            return this;
        }

        /**
         * @param type An optional filter to return only resources that match the specified type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable String type) {
            $.type = type;
            return this;
        }

        public GetReportsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetReportsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
