// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSecurityPolicyReportDatabaseViewAccessEntriesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSecurityPolicyReportDatabaseViewAccessEntriesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSecurityPolicyReportDatabaseViewAccessEntriesArgs Empty = new GetSecurityPolicyReportDatabaseViewAccessEntriesArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilterArgs>> filters;

    public Optional<Output<List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     * 
     * **Example:** query=(accessType eq &#39;SELECT&#39;) and (grantee eq &#39;ADMIN&#39;)
     * 
     */
    @Import(name="scimQuery")
    private @Nullable Output<String> scimQuery;

    /**
     * @return The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     * 
     * **Example:** query=(accessType eq &#39;SELECT&#39;) and (grantee eq &#39;ADMIN&#39;)
     * 
     */
    public Optional<Output<String>> scimQuery() {
        return Optional.ofNullable(this.scimQuery);
    }

    /**
     * The OCID of the security policy report resource.
     * 
     */
    @Import(name="securityPolicyReportId", required=true)
    private Output<String> securityPolicyReportId;

    /**
     * @return The OCID of the security policy report resource.
     * 
     */
    public Output<String> securityPolicyReportId() {
        return this.securityPolicyReportId;
    }

    /**
     * A filter to return only items related to a specific target OCID.
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    private GetSecurityPolicyReportDatabaseViewAccessEntriesArgs() {}

    private GetSecurityPolicyReportDatabaseViewAccessEntriesArgs(GetSecurityPolicyReportDatabaseViewAccessEntriesArgs $) {
        this.filters = $.filters;
        this.scimQuery = $.scimQuery;
        this.securityPolicyReportId = $.securityPolicyReportId;
        this.targetId = $.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityPolicyReportDatabaseViewAccessEntriesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityPolicyReportDatabaseViewAccessEntriesArgs $;

        public Builder() {
            $ = new GetSecurityPolicyReportDatabaseViewAccessEntriesArgs();
        }

        public Builder(GetSecurityPolicyReportDatabaseViewAccessEntriesArgs defaults) {
            $ = new GetSecurityPolicyReportDatabaseViewAccessEntriesArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSecurityPolicyReportDatabaseViewAccessEntriesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSecurityPolicyReportDatabaseViewAccessEntriesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param scimQuery The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
         * 
         * **Example:** query=(accessType eq &#39;SELECT&#39;) and (grantee eq &#39;ADMIN&#39;)
         * 
         * @return builder
         * 
         */
        public Builder scimQuery(@Nullable Output<String> scimQuery) {
            $.scimQuery = scimQuery;
            return this;
        }

        /**
         * @param scimQuery The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
         * 
         * **Example:** query=(accessType eq &#39;SELECT&#39;) and (grantee eq &#39;ADMIN&#39;)
         * 
         * @return builder
         * 
         */
        public Builder scimQuery(String scimQuery) {
            return scimQuery(Output.of(scimQuery));
        }

        /**
         * @param securityPolicyReportId The OCID of the security policy report resource.
         * 
         * @return builder
         * 
         */
        public Builder securityPolicyReportId(Output<String> securityPolicyReportId) {
            $.securityPolicyReportId = securityPolicyReportId;
            return this;
        }

        /**
         * @param securityPolicyReportId The OCID of the security policy report resource.
         * 
         * @return builder
         * 
         */
        public Builder securityPolicyReportId(String securityPolicyReportId) {
            return securityPolicyReportId(Output.of(securityPolicyReportId));
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        public GetSecurityPolicyReportDatabaseViewAccessEntriesArgs build() {
            if ($.securityPolicyReportId == null) {
                throw new MissingRequiredPropertyException("GetSecurityPolicyReportDatabaseViewAccessEntriesArgs", "securityPolicyReportId");
            }
            return $;
        }
    }

}
