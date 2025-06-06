// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDomainsMyRequestableGroupsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainsMyRequestableGroupsPlainArgs Empty = new GetDomainsMyRequestableGroupsPlainArgs();

    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Import(name="authorization")
    private @Nullable String authorization;

    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Optional<String> authorization() {
        return Optional.ofNullable(this.authorization);
    }

    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Import(name="idcsEndpoint", required=true)
    private String idcsEndpoint;

    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }

    /**
     * OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
     * 
     */
    @Import(name="myRequestableGroupCount")
    private @Nullable Integer myRequestableGroupCount;

    /**
     * @return OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
     * 
     */
    public Optional<Integer> myRequestableGroupCount() {
        return Optional.ofNullable(this.myRequestableGroupCount);
    }

    /**
     * OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
     * 
     */
    @Import(name="myRequestableGroupFilter")
    private @Nullable String myRequestableGroupFilter;

    /**
     * @return OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
     * 
     */
    public Optional<String> myRequestableGroupFilter() {
        return Optional.ofNullable(this.myRequestableGroupFilter);
    }

    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Import(name="resourceTypeSchemaVersion")
    private @Nullable String resourceTypeSchemaVersion;

    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }

    @Import(name="sortBy")
    private @Nullable String sortBy;

    public Optional<String> sortBy() {
        return Optional.ofNullable(this.sortBy);
    }

    @Import(name="sortOrder")
    private @Nullable String sortOrder;

    public Optional<String> sortOrder() {
        return Optional.ofNullable(this.sortOrder);
    }

    /**
     * OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
     * 
     */
    @Import(name="startIndex")
    private @Nullable Integer startIndex;

    /**
     * @return OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
     * 
     */
    public Optional<Integer> startIndex() {
        return Optional.ofNullable(this.startIndex);
    }

    private GetDomainsMyRequestableGroupsPlainArgs() {}

    private GetDomainsMyRequestableGroupsPlainArgs(GetDomainsMyRequestableGroupsPlainArgs $) {
        this.authorization = $.authorization;
        this.compartmentId = $.compartmentId;
        this.idcsEndpoint = $.idcsEndpoint;
        this.myRequestableGroupCount = $.myRequestableGroupCount;
        this.myRequestableGroupFilter = $.myRequestableGroupFilter;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
        this.sortBy = $.sortBy;
        this.sortOrder = $.sortOrder;
        this.startIndex = $.startIndex;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainsMyRequestableGroupsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainsMyRequestableGroupsPlainArgs $;

        public Builder() {
            $ = new GetDomainsMyRequestableGroupsPlainArgs();
        }

        public Builder(GetDomainsMyRequestableGroupsPlainArgs defaults) {
            $ = new GetDomainsMyRequestableGroupsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param authorization The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(@Nullable String authorization) {
            $.authorization = authorization;
            return this;
        }

        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(String idcsEndpoint) {
            $.idcsEndpoint = idcsEndpoint;
            return this;
        }

        /**
         * @param myRequestableGroupCount OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
         * 
         * @return builder
         * 
         */
        public Builder myRequestableGroupCount(@Nullable Integer myRequestableGroupCount) {
            $.myRequestableGroupCount = myRequestableGroupCount;
            return this;
        }

        /**
         * @param myRequestableGroupFilter OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
         * 
         * @return builder
         * 
         */
        public Builder myRequestableGroupFilter(@Nullable String myRequestableGroupFilter) {
            $.myRequestableGroupFilter = myRequestableGroupFilter;
            return this;
        }

        /**
         * @param resourceTypeSchemaVersion An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {
            $.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }

        public Builder sortBy(@Nullable String sortBy) {
            $.sortBy = sortBy;
            return this;
        }

        public Builder sortOrder(@Nullable String sortOrder) {
            $.sortOrder = sortOrder;
            return this;
        }

        /**
         * @param startIndex OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
         * 
         * @return builder
         * 
         */
        public Builder startIndex(@Nullable Integer startIndex) {
            $.startIndex = startIndex;
            return this;
        }

        public GetDomainsMyRequestableGroupsPlainArgs build() {
            if ($.idcsEndpoint == null) {
                throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsPlainArgs", "idcsEndpoint");
            }
            return $;
        }
    }

}
