// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSqlFirewallAllowedSqlAnalyticsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSqlFirewallAllowedSqlAnalyticsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSqlFirewallAllowedSqlAnalyticsPlainArgs Empty = new GetSqlFirewallAllowedSqlAnalyticsPlainArgs();

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

    @Import(name="filters")
    private @Nullable List<GetSqlFirewallAllowedSqlAnalyticsFilter> filters;

    public Optional<List<GetSqlFirewallAllowedSqlAnalyticsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The group by parameter to summarize the allowed SQL aggregation.
     * 
     */
    @Import(name="groupBies")
    private @Nullable List<String> groupBies;

    /**
     * @return The group by parameter to summarize the allowed SQL aggregation.
     * 
     */
    public Optional<List<String>> groupBies() {
        return Optional.ofNullable(this.groupBies);
    }

    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     * 
     * **Example:** query=(currentUser eq &#39;SCOTT&#39;) and (topLevel eq &#39;YES&#39;)
     * 
     */
    @Import(name="scimQuery")
    private @Nullable String scimQuery;

    /**
     * @return The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     * 
     * **Example:** query=(currentUser eq &#39;SCOTT&#39;) and (topLevel eq &#39;YES&#39;)
     * 
     */
    public Optional<String> scimQuery() {
        return Optional.ofNullable(this.scimQuery);
    }

    private GetSqlFirewallAllowedSqlAnalyticsPlainArgs() {}

    private GetSqlFirewallAllowedSqlAnalyticsPlainArgs(GetSqlFirewallAllowedSqlAnalyticsPlainArgs $) {
        this.accessLevel = $.accessLevel;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.filters = $.filters;
        this.groupBies = $.groupBies;
        this.scimQuery = $.scimQuery;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSqlFirewallAllowedSqlAnalyticsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSqlFirewallAllowedSqlAnalyticsPlainArgs $;

        public Builder() {
            $ = new GetSqlFirewallAllowedSqlAnalyticsPlainArgs();
        }

        public Builder(GetSqlFirewallAllowedSqlAnalyticsPlainArgs defaults) {
            $ = new GetSqlFirewallAllowedSqlAnalyticsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetSqlFirewallAllowedSqlAnalyticsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSqlFirewallAllowedSqlAnalyticsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param groupBies The group by parameter to summarize the allowed SQL aggregation.
         * 
         * @return builder
         * 
         */
        public Builder groupBies(@Nullable List<String> groupBies) {
            $.groupBies = groupBies;
            return this;
        }

        /**
         * @param groupBies The group by parameter to summarize the allowed SQL aggregation.
         * 
         * @return builder
         * 
         */
        public Builder groupBies(String... groupBies) {
            return groupBies(List.of(groupBies));
        }

        /**
         * @param scimQuery The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
         * 
         * **Example:** query=(currentUser eq &#39;SCOTT&#39;) and (topLevel eq &#39;YES&#39;)
         * 
         * @return builder
         * 
         */
        public Builder scimQuery(@Nullable String scimQuery) {
            $.scimQuery = scimQuery;
            return this;
        }

        public GetSqlFirewallAllowedSqlAnalyticsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetSqlFirewallAllowedSqlAnalyticsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
