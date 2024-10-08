// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSecurityAssessmentFindingsChangeAuditLogsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs Empty = new GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetSecurityAssessmentFindingsChangeAuditLogsFilter> filters;

    public Optional<List<GetSecurityAssessmentFindingsChangeAuditLogsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The unique key that identifies the finding. It is a string and unique within a security assessment.
     * 
     */
    @Import(name="findingKey")
    private @Nullable String findingKey;

    /**
     * @return The unique key that identifies the finding. It is a string and unique within a security assessment.
     * 
     */
    public Optional<String> findingKey() {
        return Optional.ofNullable(this.findingKey);
    }

    /**
     * The unique title that identifies the finding. It is a string and unique within a security assessment.
     * 
     */
    @Import(name="findingTitle")
    private @Nullable String findingTitle;

    /**
     * @return The unique title that identifies the finding. It is a string and unique within a security assessment.
     * 
     */
    public Optional<String> findingTitle() {
        return Optional.ofNullable(this.findingTitle);
    }

    /**
     * A filter to check findings whose risks were deferred by the user.
     * 
     */
    @Import(name="isRiskDeferred")
    private @Nullable Boolean isRiskDeferred;

    /**
     * @return A filter to check findings whose risks were deferred by the user.
     * 
     */
    public Optional<Boolean> isRiskDeferred() {
        return Optional.ofNullable(this.isRiskDeferred);
    }

    /**
     * A filter to check which user modified the risk level of the finding.
     * 
     */
    @Import(name="modifiedBy")
    private @Nullable String modifiedBy;

    /**
     * @return A filter to check which user modified the risk level of the finding.
     * 
     */
    public Optional<String> modifiedBy() {
        return Optional.ofNullable(this.modifiedBy);
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
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeUpdatedGreaterThanOrEqualTo")
    private @Nullable String timeUpdatedGreaterThanOrEqualTo;

    /**
     * @return Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<String> timeUpdatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeUpdatedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeUpdatedLessThan")
    private @Nullable String timeUpdatedLessThan;

    /**
     * @return Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<String> timeUpdatedLessThan() {
        return Optional.ofNullable(this.timeUpdatedLessThan);
    }

    /**
     * Specifying `TimeValidUntilGreaterThanOrEqualToQueryParam` parameter  will retrieve all items for which the risk level modification by user will  no longer be valid greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     * **Example:** 2016-12-19T00:00:00.000Z
     * 
     */
    @Import(name="timeValidUntilGreaterThanOrEqualTo")
    private @Nullable String timeValidUntilGreaterThanOrEqualTo;

    /**
     * @return Specifying `TimeValidUntilGreaterThanOrEqualToQueryParam` parameter  will retrieve all items for which the risk level modification by user will  no longer be valid greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     * **Example:** 2016-12-19T00:00:00.000Z
     * 
     */
    public Optional<String> timeValidUntilGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeValidUntilGreaterThanOrEqualTo);
    }

    /**
     * Specifying `TimeValidUntilLessThanQueryParam` parameter will retrieve all items for which the risk level modification by user will  be valid until less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     * **Example:** 2016-12-19T00:00:00.000Z
     * 
     */
    @Import(name="timeValidUntilLessThan")
    private @Nullable String timeValidUntilLessThan;

    /**
     * @return Specifying `TimeValidUntilLessThanQueryParam` parameter will retrieve all items for which the risk level modification by user will  be valid until less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     * **Example:** 2016-12-19T00:00:00.000Z
     * 
     */
    public Optional<String> timeValidUntilLessThan() {
        return Optional.ofNullable(this.timeValidUntilLessThan);
    }

    private GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs() {}

    private GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs(GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs $) {
        this.filters = $.filters;
        this.findingKey = $.findingKey;
        this.findingTitle = $.findingTitle;
        this.isRiskDeferred = $.isRiskDeferred;
        this.modifiedBy = $.modifiedBy;
        this.securityAssessmentId = $.securityAssessmentId;
        this.severity = $.severity;
        this.timeUpdatedGreaterThanOrEqualTo = $.timeUpdatedGreaterThanOrEqualTo;
        this.timeUpdatedLessThan = $.timeUpdatedLessThan;
        this.timeValidUntilGreaterThanOrEqualTo = $.timeValidUntilGreaterThanOrEqualTo;
        this.timeValidUntilLessThan = $.timeValidUntilLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs $;

        public Builder() {
            $ = new GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs();
        }

        public Builder(GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs defaults) {
            $ = new GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetSecurityAssessmentFindingsChangeAuditLogsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSecurityAssessmentFindingsChangeAuditLogsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param findingKey The unique key that identifies the finding. It is a string and unique within a security assessment.
         * 
         * @return builder
         * 
         */
        public Builder findingKey(@Nullable String findingKey) {
            $.findingKey = findingKey;
            return this;
        }

        /**
         * @param findingTitle The unique title that identifies the finding. It is a string and unique within a security assessment.
         * 
         * @return builder
         * 
         */
        public Builder findingTitle(@Nullable String findingTitle) {
            $.findingTitle = findingTitle;
            return this;
        }

        /**
         * @param isRiskDeferred A filter to check findings whose risks were deferred by the user.
         * 
         * @return builder
         * 
         */
        public Builder isRiskDeferred(@Nullable Boolean isRiskDeferred) {
            $.isRiskDeferred = isRiskDeferred;
            return this;
        }

        /**
         * @param modifiedBy A filter to check which user modified the risk level of the finding.
         * 
         * @return builder
         * 
         */
        public Builder modifiedBy(@Nullable String modifiedBy) {
            $.modifiedBy = modifiedBy;
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
         * @param timeUpdatedGreaterThanOrEqualTo Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdatedGreaterThanOrEqualTo(@Nullable String timeUpdatedGreaterThanOrEqualTo) {
            $.timeUpdatedGreaterThanOrEqualTo = timeUpdatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeUpdatedLessThan Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdatedLessThan(@Nullable String timeUpdatedLessThan) {
            $.timeUpdatedLessThan = timeUpdatedLessThan;
            return this;
        }

        /**
         * @param timeValidUntilGreaterThanOrEqualTo Specifying `TimeValidUntilGreaterThanOrEqualToQueryParam` parameter  will retrieve all items for which the risk level modification by user will  no longer be valid greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * **Example:** 2016-12-19T00:00:00.000Z
         * 
         * @return builder
         * 
         */
        public Builder timeValidUntilGreaterThanOrEqualTo(@Nullable String timeValidUntilGreaterThanOrEqualTo) {
            $.timeValidUntilGreaterThanOrEqualTo = timeValidUntilGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeValidUntilLessThan Specifying `TimeValidUntilLessThanQueryParam` parameter will retrieve all items for which the risk level modification by user will  be valid until less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * **Example:** 2016-12-19T00:00:00.000Z
         * 
         * @return builder
         * 
         */
        public Builder timeValidUntilLessThan(@Nullable String timeValidUntilLessThan) {
            $.timeValidUntilLessThan = timeValidUntilLessThan;
            return this;
        }

        public GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs build() {
            if ($.securityAssessmentId == null) {
                throw new MissingRequiredPropertyException("GetSecurityAssessmentFindingsChangeAuditLogsPlainArgs", "securityAssessmentId");
            }
            return $;
        }
    }

}
