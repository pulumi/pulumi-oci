// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSecurityAssessmentFindingsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSecurityAssessmentFindingsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSecurityAssessmentFindingsPlainArgs Empty = new GetSecurityAssessmentFindingsPlainArgs();

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
     * Specifies a subset of fields to be returned in the response.
     * 
     */
    @Import(name="fields")
    private @Nullable List<String> fields;

    /**
     * @return Specifies a subset of fields to be returned in the response.
     * 
     */
    public Optional<List<String>> fields() {
        return Optional.ofNullable(this.fields);
    }

    @Import(name="filters")
    private @Nullable List<GetSecurityAssessmentFindingsFilter> filters;

    public Optional<List<GetSecurityAssessmentFindingsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Each finding in security assessment has an associated key (think of key as a finding&#39;s name). For a given finding, the key will be the same across targets. The user can use these keys to filter the findings.
     * 
     */
    @Import(name="findingKey")
    private @Nullable String findingKey;

    /**
     * @return Each finding in security assessment has an associated key (think of key as a finding&#39;s name). For a given finding, the key will be the same across targets. The user can use these keys to filter the findings.
     * 
     */
    public Optional<String> findingKey() {
        return Optional.ofNullable(this.findingKey);
    }

    /**
     * A filter to return only the findings that are marked as top findings.
     * 
     */
    @Import(name="isTopFinding")
    private @Nullable Boolean isTopFinding;

    /**
     * @return A filter to return only the findings that are marked as top findings.
     * 
     */
    public Optional<Boolean> isTopFinding() {
        return Optional.ofNullable(this.isTopFinding);
    }

    /**
     * An optional filter to return only findings that match the specified reference.
     * 
     */
    @Import(name="references")
    private @Nullable String references;

    /**
     * @return An optional filter to return only findings that match the specified reference.
     * 
     */
    public Optional<String> references() {
        return Optional.ofNullable(this.references);
    }

    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     * 
     * **Example:** | scimQuery=(severity eq &#39;high&#39;) and (targetId eq &#39;target_1&#39;) scimQuery=(category eq &#34;Users&#34;) and (targetId eq &#34;target_1&#34;) scimQuery=(reference eq &#39;CIS&#39;) and (targetId eq &#39;target_1&#39;)
     * Supported fields: severity findingKey reference targetId isTopFinding title category remarks details summary isRiskModified
     * 
     */
    @Import(name="scimQuery")
    private @Nullable String scimQuery;

    /**
     * @return The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     * 
     * **Example:** | scimQuery=(severity eq &#39;high&#39;) and (targetId eq &#39;target_1&#39;) scimQuery=(category eq &#34;Users&#34;) and (targetId eq &#34;target_1&#34;) scimQuery=(reference eq &#39;CIS&#39;) and (targetId eq &#39;target_1&#39;)
     * Supported fields: severity findingKey reference targetId isTopFinding title category remarks details summary isRiskModified
     * 
     */
    public Optional<String> scimQuery() {
        return Optional.ofNullable(this.scimQuery);
    }

    /**
     * The OCID of the security assessment.
     * 
     */
    @Import(name="securityAssessmentId", required=true)
    private String securityAssessmentId;

    /**
     * @return The OCID of the security assessment.
     * 
     */
    public String securityAssessmentId() {
        return this.securityAssessmentId;
    }

    /**
     * A filter to return only findings of a particular risk level.
     * 
     */
    @Import(name="severity")
    private @Nullable String severity;

    /**
     * @return A filter to return only findings of a particular risk level.
     * 
     */
    public Optional<String> severity() {
        return Optional.ofNullable(this.severity);
    }

    /**
     * A filter to return only the findings that match the specified lifecycle states.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only the findings that match the specified lifecycle states.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only items related to a specific target OCID.
     * 
     */
    @Import(name="targetId")
    private @Nullable String targetId;

    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    private GetSecurityAssessmentFindingsPlainArgs() {}

    private GetSecurityAssessmentFindingsPlainArgs(GetSecurityAssessmentFindingsPlainArgs $) {
        this.accessLevel = $.accessLevel;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.fields = $.fields;
        this.filters = $.filters;
        this.findingKey = $.findingKey;
        this.isTopFinding = $.isTopFinding;
        this.references = $.references;
        this.scimQuery = $.scimQuery;
        this.securityAssessmentId = $.securityAssessmentId;
        this.severity = $.severity;
        this.state = $.state;
        this.targetId = $.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityAssessmentFindingsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityAssessmentFindingsPlainArgs $;

        public Builder() {
            $ = new GetSecurityAssessmentFindingsPlainArgs();
        }

        public Builder(GetSecurityAssessmentFindingsPlainArgs defaults) {
            $ = new GetSecurityAssessmentFindingsPlainArgs(Objects.requireNonNull(defaults));
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
         * @param fields Specifies a subset of fields to be returned in the response.
         * 
         * @return builder
         * 
         */
        public Builder fields(@Nullable List<String> fields) {
            $.fields = fields;
            return this;
        }

        /**
         * @param fields Specifies a subset of fields to be returned in the response.
         * 
         * @return builder
         * 
         */
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }

        public Builder filters(@Nullable List<GetSecurityAssessmentFindingsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSecurityAssessmentFindingsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param findingKey Each finding in security assessment has an associated key (think of key as a finding&#39;s name). For a given finding, the key will be the same across targets. The user can use these keys to filter the findings.
         * 
         * @return builder
         * 
         */
        public Builder findingKey(@Nullable String findingKey) {
            $.findingKey = findingKey;
            return this;
        }

        /**
         * @param isTopFinding A filter to return only the findings that are marked as top findings.
         * 
         * @return builder
         * 
         */
        public Builder isTopFinding(@Nullable Boolean isTopFinding) {
            $.isTopFinding = isTopFinding;
            return this;
        }

        /**
         * @param references An optional filter to return only findings that match the specified reference.
         * 
         * @return builder
         * 
         */
        public Builder references(@Nullable String references) {
            $.references = references;
            return this;
        }

        /**
         * @param scimQuery The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
         * 
         * **Example:** | scimQuery=(severity eq &#39;high&#39;) and (targetId eq &#39;target_1&#39;) scimQuery=(category eq &#34;Users&#34;) and (targetId eq &#34;target_1&#34;) scimQuery=(reference eq &#39;CIS&#39;) and (targetId eq &#39;target_1&#39;)
         * Supported fields: severity findingKey reference targetId isTopFinding title category remarks details summary isRiskModified
         * 
         * @return builder
         * 
         */
        public Builder scimQuery(@Nullable String scimQuery) {
            $.scimQuery = scimQuery;
            return this;
        }

        /**
         * @param securityAssessmentId The OCID of the security assessment.
         * 
         * @return builder
         * 
         */
        public Builder securityAssessmentId(String securityAssessmentId) {
            $.securityAssessmentId = securityAssessmentId;
            return this;
        }

        /**
         * @param severity A filter to return only findings of a particular risk level.
         * 
         * @return builder
         * 
         */
        public Builder severity(@Nullable String severity) {
            $.severity = severity;
            return this;
        }

        /**
         * @param state A filter to return only the findings that match the specified lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable String targetId) {
            $.targetId = targetId;
            return this;
        }

        public GetSecurityAssessmentFindingsPlainArgs build() {
            if ($.securityAssessmentId == null) {
                throw new MissingRequiredPropertyException("GetSecurityAssessmentFindingsPlainArgs", "securityAssessmentId");
            }
            return $;
        }
    }

}
