// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetListUserGrantsFilterArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetListUserGrantsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetListUserGrantsArgs Empty = new GetListUserGrantsArgs();

    /**
     * A filter to return only items that match the specified user grant depth level.
     * 
     */
    @Import(name="depthLevel")
    private @Nullable Output<Integer> depthLevel;

    /**
     * @return A filter to return only items that match the specified user grant depth level.
     * 
     */
    public Optional<Output<Integer>> depthLevel() {
        return Optional.ofNullable(this.depthLevel);
    }

    /**
     * A filter to return only items that are at a level greater than or equal to the specified user grant depth level.
     * 
     */
    @Import(name="depthLevelGreaterThanOrEqualTo")
    private @Nullable Output<Integer> depthLevelGreaterThanOrEqualTo;

    /**
     * @return A filter to return only items that are at a level greater than or equal to the specified user grant depth level.
     * 
     */
    public Optional<Output<Integer>> depthLevelGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.depthLevelGreaterThanOrEqualTo);
    }

    /**
     * A filter to return only items that are at a level less than the specified user grant depth level.
     * 
     */
    @Import(name="depthLevelLessThan")
    private @Nullable Output<Integer> depthLevelLessThan;

    /**
     * @return A filter to return only items that are at a level less than the specified user grant depth level.
     * 
     */
    public Optional<Output<Integer>> depthLevelLessThan() {
        return Optional.ofNullable(this.depthLevelLessThan);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetListUserGrantsFilterArgs>> filters;

    public Optional<Output<List<GetListUserGrantsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only items that match the specified user grant key.
     * 
     */
    @Import(name="grantKey")
    private @Nullable Output<String> grantKey;

    /**
     * @return A filter to return only items that match the specified user grant key.
     * 
     */
    public Optional<Output<String>> grantKey() {
        return Optional.ofNullable(this.grantKey);
    }

    /**
     * A filter to return only items that match the specified user grant name.
     * 
     */
    @Import(name="grantName")
    private @Nullable Output<String> grantName;

    /**
     * @return A filter to return only items that match the specified user grant name.
     * 
     */
    public Optional<Output<String>> grantName() {
        return Optional.ofNullable(this.grantName);
    }

    /**
     * A filter to return only items that match the specified user privilege category.
     * 
     */
    @Import(name="privilegeCategory")
    private @Nullable Output<String> privilegeCategory;

    /**
     * @return A filter to return only items that match the specified user privilege category.
     * 
     */
    public Optional<Output<String>> privilegeCategory() {
        return Optional.ofNullable(this.privilegeCategory);
    }

    /**
     * A filter to return only items that match the specified privilege grant type.
     * 
     */
    @Import(name="privilegeType")
    private @Nullable Output<String> privilegeType;

    /**
     * @return A filter to return only items that match the specified privilege grant type.
     * 
     */
    public Optional<Output<String>> privilegeType() {
        return Optional.ofNullable(this.privilegeType);
    }

    /**
     * The OCID of the user assessment.
     * 
     */
    @Import(name="userAssessmentId", required=true)
    private Output<String> userAssessmentId;

    /**
     * @return The OCID of the user assessment.
     * 
     */
    public Output<String> userAssessmentId() {
        return this.userAssessmentId;
    }

    /**
     * The unique user key. This is a system-generated identifier. ListUsers gets the user key for a user.
     * 
     */
    @Import(name="userKey", required=true)
    private Output<String> userKey;

    /**
     * @return The unique user key. This is a system-generated identifier. ListUsers gets the user key for a user.
     * 
     */
    public Output<String> userKey() {
        return this.userKey;
    }

    private GetListUserGrantsArgs() {}

    private GetListUserGrantsArgs(GetListUserGrantsArgs $) {
        this.depthLevel = $.depthLevel;
        this.depthLevelGreaterThanOrEqualTo = $.depthLevelGreaterThanOrEqualTo;
        this.depthLevelLessThan = $.depthLevelLessThan;
        this.filters = $.filters;
        this.grantKey = $.grantKey;
        this.grantName = $.grantName;
        this.privilegeCategory = $.privilegeCategory;
        this.privilegeType = $.privilegeType;
        this.userAssessmentId = $.userAssessmentId;
        this.userKey = $.userKey;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetListUserGrantsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetListUserGrantsArgs $;

        public Builder() {
            $ = new GetListUserGrantsArgs();
        }

        public Builder(GetListUserGrantsArgs defaults) {
            $ = new GetListUserGrantsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param depthLevel A filter to return only items that match the specified user grant depth level.
         * 
         * @return builder
         * 
         */
        public Builder depthLevel(@Nullable Output<Integer> depthLevel) {
            $.depthLevel = depthLevel;
            return this;
        }

        /**
         * @param depthLevel A filter to return only items that match the specified user grant depth level.
         * 
         * @return builder
         * 
         */
        public Builder depthLevel(Integer depthLevel) {
            return depthLevel(Output.of(depthLevel));
        }

        /**
         * @param depthLevelGreaterThanOrEqualTo A filter to return only items that are at a level greater than or equal to the specified user grant depth level.
         * 
         * @return builder
         * 
         */
        public Builder depthLevelGreaterThanOrEqualTo(@Nullable Output<Integer> depthLevelGreaterThanOrEqualTo) {
            $.depthLevelGreaterThanOrEqualTo = depthLevelGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param depthLevelGreaterThanOrEqualTo A filter to return only items that are at a level greater than or equal to the specified user grant depth level.
         * 
         * @return builder
         * 
         */
        public Builder depthLevelGreaterThanOrEqualTo(Integer depthLevelGreaterThanOrEqualTo) {
            return depthLevelGreaterThanOrEqualTo(Output.of(depthLevelGreaterThanOrEqualTo));
        }

        /**
         * @param depthLevelLessThan A filter to return only items that are at a level less than the specified user grant depth level.
         * 
         * @return builder
         * 
         */
        public Builder depthLevelLessThan(@Nullable Output<Integer> depthLevelLessThan) {
            $.depthLevelLessThan = depthLevelLessThan;
            return this;
        }

        /**
         * @param depthLevelLessThan A filter to return only items that are at a level less than the specified user grant depth level.
         * 
         * @return builder
         * 
         */
        public Builder depthLevelLessThan(Integer depthLevelLessThan) {
            return depthLevelLessThan(Output.of(depthLevelLessThan));
        }

        public Builder filters(@Nullable Output<List<GetListUserGrantsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetListUserGrantsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetListUserGrantsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param grantKey A filter to return only items that match the specified user grant key.
         * 
         * @return builder
         * 
         */
        public Builder grantKey(@Nullable Output<String> grantKey) {
            $.grantKey = grantKey;
            return this;
        }

        /**
         * @param grantKey A filter to return only items that match the specified user grant key.
         * 
         * @return builder
         * 
         */
        public Builder grantKey(String grantKey) {
            return grantKey(Output.of(grantKey));
        }

        /**
         * @param grantName A filter to return only items that match the specified user grant name.
         * 
         * @return builder
         * 
         */
        public Builder grantName(@Nullable Output<String> grantName) {
            $.grantName = grantName;
            return this;
        }

        /**
         * @param grantName A filter to return only items that match the specified user grant name.
         * 
         * @return builder
         * 
         */
        public Builder grantName(String grantName) {
            return grantName(Output.of(grantName));
        }

        /**
         * @param privilegeCategory A filter to return only items that match the specified user privilege category.
         * 
         * @return builder
         * 
         */
        public Builder privilegeCategory(@Nullable Output<String> privilegeCategory) {
            $.privilegeCategory = privilegeCategory;
            return this;
        }

        /**
         * @param privilegeCategory A filter to return only items that match the specified user privilege category.
         * 
         * @return builder
         * 
         */
        public Builder privilegeCategory(String privilegeCategory) {
            return privilegeCategory(Output.of(privilegeCategory));
        }

        /**
         * @param privilegeType A filter to return only items that match the specified privilege grant type.
         * 
         * @return builder
         * 
         */
        public Builder privilegeType(@Nullable Output<String> privilegeType) {
            $.privilegeType = privilegeType;
            return this;
        }

        /**
         * @param privilegeType A filter to return only items that match the specified privilege grant type.
         * 
         * @return builder
         * 
         */
        public Builder privilegeType(String privilegeType) {
            return privilegeType(Output.of(privilegeType));
        }

        /**
         * @param userAssessmentId The OCID of the user assessment.
         * 
         * @return builder
         * 
         */
        public Builder userAssessmentId(Output<String> userAssessmentId) {
            $.userAssessmentId = userAssessmentId;
            return this;
        }

        /**
         * @param userAssessmentId The OCID of the user assessment.
         * 
         * @return builder
         * 
         */
        public Builder userAssessmentId(String userAssessmentId) {
            return userAssessmentId(Output.of(userAssessmentId));
        }

        /**
         * @param userKey The unique user key. This is a system-generated identifier. ListUsers gets the user key for a user.
         * 
         * @return builder
         * 
         */
        public Builder userKey(Output<String> userKey) {
            $.userKey = userKey;
            return this;
        }

        /**
         * @param userKey The unique user key. This is a system-generated identifier. ListUsers gets the user key for a user.
         * 
         * @return builder
         * 
         */
        public Builder userKey(String userKey) {
            return userKey(Output.of(userKey));
        }

        public GetListUserGrantsArgs build() {
            $.userAssessmentId = Objects.requireNonNull($.userAssessmentId, "expected parameter 'userAssessmentId' to be non-null");
            $.userKey = Objects.requireNonNull($.userKey, "expected parameter 'userKey' to be non-null");
            return $;
        }
    }

}