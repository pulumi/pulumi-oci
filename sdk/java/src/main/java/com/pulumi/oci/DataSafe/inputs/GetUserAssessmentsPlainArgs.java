// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetUserAssessmentsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetUserAssessmentsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUserAssessmentsPlainArgs Empty = new GetUserAssessmentsPlainArgs();

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
     * A filter to return only resources that match the specified display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetUserAssessmentsFilter> filters;

    public Optional<List<GetUserAssessmentsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only user assessments that are set as baseline.
     * 
     */
    @Import(name="isBaseline")
    private @Nullable Boolean isBaseline;

    /**
     * @return A filter to return only user assessments that are set as baseline.
     * 
     */
    public Optional<Boolean> isBaseline() {
        return Optional.ofNullable(this.isBaseline);
    }

    /**
     * A filter to return only user assessments of type SAVE_SCHEDULE.
     * 
     */
    @Import(name="isScheduleAssessment")
    private @Nullable Boolean isScheduleAssessment;

    /**
     * @return A filter to return only user assessments of type SAVE_SCHEDULE.
     * 
     */
    public Optional<Boolean> isScheduleAssessment() {
        return Optional.ofNullable(this.isScheduleAssessment);
    }

    /**
     * The OCID of the user assessment of type SAVE_SCHEDULE.
     * 
     */
    @Import(name="scheduleUserAssessmentId")
    private @Nullable String scheduleUserAssessmentId;

    /**
     * @return The OCID of the user assessment of type SAVE_SCHEDULE.
     * 
     */
    public Optional<String> scheduleUserAssessmentId() {
        return Optional.ofNullable(this.scheduleUserAssessmentId);
    }

    /**
     * The current state of the user assessment.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the user assessment.
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

    /**
     * A filter to return only user assessments that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using timeCreatedGreaterThanOrEqualTo parameter retrieves all assessments created after that date.
     * 
     */
    @Import(name="timeCreatedGreaterThanOrEqualTo")
    private @Nullable String timeCreatedGreaterThanOrEqualTo;

    /**
     * @return A filter to return only user assessments that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using timeCreatedGreaterThanOrEqualTo parameter retrieves all assessments created after that date.
     * 
     */
    public Optional<String> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }

    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeCreatedLessThan")
    private @Nullable String timeCreatedLessThan;

    /**
     * @return Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<String> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    /**
     * A filter to return user assessments that were created by either the system or by a user only.
     * 
     */
    @Import(name="triggeredBy")
    private @Nullable String triggeredBy;

    /**
     * @return A filter to return user assessments that were created by either the system or by a user only.
     * 
     */
    public Optional<String> triggeredBy() {
        return Optional.ofNullable(this.triggeredBy);
    }

    /**
     * A filter to return only items that match the specified assessment type.
     * 
     */
    @Import(name="type")
    private @Nullable String type;

    /**
     * @return A filter to return only items that match the specified assessment type.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    private GetUserAssessmentsPlainArgs() {}

    private GetUserAssessmentsPlainArgs(GetUserAssessmentsPlainArgs $) {
        this.accessLevel = $.accessLevel;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isBaseline = $.isBaseline;
        this.isScheduleAssessment = $.isScheduleAssessment;
        this.scheduleUserAssessmentId = $.scheduleUserAssessmentId;
        this.state = $.state;
        this.targetId = $.targetId;
        this.timeCreatedGreaterThanOrEqualTo = $.timeCreatedGreaterThanOrEqualTo;
        this.timeCreatedLessThan = $.timeCreatedLessThan;
        this.triggeredBy = $.triggeredBy;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUserAssessmentsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUserAssessmentsPlainArgs $;

        public Builder() {
            $ = new GetUserAssessmentsPlainArgs();
        }

        public Builder(GetUserAssessmentsPlainArgs defaults) {
            $ = new GetUserAssessmentsPlainArgs(Objects.requireNonNull(defaults));
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
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetUserAssessmentsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetUserAssessmentsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isBaseline A filter to return only user assessments that are set as baseline.
         * 
         * @return builder
         * 
         */
        public Builder isBaseline(@Nullable Boolean isBaseline) {
            $.isBaseline = isBaseline;
            return this;
        }

        /**
         * @param isScheduleAssessment A filter to return only user assessments of type SAVE_SCHEDULE.
         * 
         * @return builder
         * 
         */
        public Builder isScheduleAssessment(@Nullable Boolean isScheduleAssessment) {
            $.isScheduleAssessment = isScheduleAssessment;
            return this;
        }

        /**
         * @param scheduleUserAssessmentId The OCID of the user assessment of type SAVE_SCHEDULE.
         * 
         * @return builder
         * 
         */
        public Builder scheduleUserAssessmentId(@Nullable String scheduleUserAssessmentId) {
            $.scheduleUserAssessmentId = scheduleUserAssessmentId;
            return this;
        }

        /**
         * @param state The current state of the user assessment.
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

        /**
         * @param timeCreatedGreaterThanOrEqualTo A filter to return only user assessments that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using timeCreatedGreaterThanOrEqualTo parameter retrieves all assessments created after that date.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable String timeCreatedGreaterThanOrEqualTo) {
            $.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeCreatedLessThan Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedLessThan(@Nullable String timeCreatedLessThan) {
            $.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }

        /**
         * @param triggeredBy A filter to return user assessments that were created by either the system or by a user only.
         * 
         * @return builder
         * 
         */
        public Builder triggeredBy(@Nullable String triggeredBy) {
            $.triggeredBy = triggeredBy;
            return this;
        }

        /**
         * @param type A filter to return only items that match the specified assessment type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable String type) {
            $.type = type;
            return this;
        }

        public GetUserAssessmentsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}