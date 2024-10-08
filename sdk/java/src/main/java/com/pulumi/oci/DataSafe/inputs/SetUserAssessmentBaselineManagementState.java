// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SetUserAssessmentBaselineManagementState extends com.pulumi.resources.ResourceArgs {

    public static final SetUserAssessmentBaselineManagementState Empty = new SetUserAssessmentBaselineManagementState();

    @Import(name="assessmentIds")
    private @Nullable Output<List<String>> assessmentIds;

    public Optional<Output<List<String>>> assessmentIds() {
        return Optional.ofNullable(this.assessmentIds);
    }

    /**
     * The compartment OCID of the target.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The compartment OCID of the target.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The target OCID for which UA needs to be set as baseline.
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return The target OCID for which UA needs to be set as baseline.
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    @Import(name="userAssessmentId")
    private @Nullable Output<String> userAssessmentId;

    public Optional<Output<String>> userAssessmentId() {
        return Optional.ofNullable(this.userAssessmentId);
    }

    private SetUserAssessmentBaselineManagementState() {}

    private SetUserAssessmentBaselineManagementState(SetUserAssessmentBaselineManagementState $) {
        this.assessmentIds = $.assessmentIds;
        this.compartmentId = $.compartmentId;
        this.targetId = $.targetId;
        this.userAssessmentId = $.userAssessmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SetUserAssessmentBaselineManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SetUserAssessmentBaselineManagementState $;

        public Builder() {
            $ = new SetUserAssessmentBaselineManagementState();
        }

        public Builder(SetUserAssessmentBaselineManagementState defaults) {
            $ = new SetUserAssessmentBaselineManagementState(Objects.requireNonNull(defaults));
        }

        public Builder assessmentIds(@Nullable Output<List<String>> assessmentIds) {
            $.assessmentIds = assessmentIds;
            return this;
        }

        public Builder assessmentIds(List<String> assessmentIds) {
            return assessmentIds(Output.of(assessmentIds));
        }

        public Builder assessmentIds(String... assessmentIds) {
            return assessmentIds(List.of(assessmentIds));
        }

        /**
         * @param compartmentId The compartment OCID of the target.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment OCID of the target.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param targetId The target OCID for which UA needs to be set as baseline.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId The target OCID for which UA needs to be set as baseline.
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        public Builder userAssessmentId(@Nullable Output<String> userAssessmentId) {
            $.userAssessmentId = userAssessmentId;
            return this;
        }

        public Builder userAssessmentId(String userAssessmentId) {
            return userAssessmentId(Output.of(userAssessmentId));
        }

        public SetUserAssessmentBaselineManagementState build() {
            return $;
        }
    }

}
