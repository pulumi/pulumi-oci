// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.inputs.GetRepositoryDiffsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepositoryDiffsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepositoryDiffsPlainArgs Empty = new GetRepositoryDiffsPlainArgs();

    /**
     * The commit or reference name to compare changes against.
     * 
     */
    @Import(name="baseVersion", required=true)
    private String baseVersion;

    /**
     * @return The commit or reference name to compare changes against.
     * 
     */
    public String baseVersion() {
        return this.baseVersion;
    }

    @Import(name="filters")
    private @Nullable List<GetRepositoryDiffsFilter> filters;

    public Optional<List<GetRepositoryDiffsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Boolean value to indicate whether to use merge base or most recent revision.
     * 
     */
    @Import(name="isComparisonFromMergeBase")
    private @Nullable Boolean isComparisonFromMergeBase;

    /**
     * @return Boolean value to indicate whether to use merge base or most recent revision.
     * 
     */
    public Optional<Boolean> isComparisonFromMergeBase() {
        return Optional.ofNullable(this.isComparisonFromMergeBase);
    }

    /**
     * Unique repository identifier.
     * 
     */
    @Import(name="repositoryId", required=true)
    private String repositoryId;

    /**
     * @return Unique repository identifier.
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }

    /**
     * The target repository identifier
     * 
     */
    @Import(name="targetRepositoryId")
    private @Nullable String targetRepositoryId;

    /**
     * @return The target repository identifier
     * 
     */
    public Optional<String> targetRepositoryId() {
        return Optional.ofNullable(this.targetRepositoryId);
    }

    /**
     * The commit or reference name where changes are coming from.
     * 
     */
    @Import(name="targetVersion", required=true)
    private String targetVersion;

    /**
     * @return The commit or reference name where changes are coming from.
     * 
     */
    public String targetVersion() {
        return this.targetVersion;
    }

    private GetRepositoryDiffsPlainArgs() {}

    private GetRepositoryDiffsPlainArgs(GetRepositoryDiffsPlainArgs $) {
        this.baseVersion = $.baseVersion;
        this.filters = $.filters;
        this.isComparisonFromMergeBase = $.isComparisonFromMergeBase;
        this.repositoryId = $.repositoryId;
        this.targetRepositoryId = $.targetRepositoryId;
        this.targetVersion = $.targetVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepositoryDiffsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepositoryDiffsPlainArgs $;

        public Builder() {
            $ = new GetRepositoryDiffsPlainArgs();
        }

        public Builder(GetRepositoryDiffsPlainArgs defaults) {
            $ = new GetRepositoryDiffsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param baseVersion The commit or reference name to compare changes against.
         * 
         * @return builder
         * 
         */
        public Builder baseVersion(String baseVersion) {
            $.baseVersion = baseVersion;
            return this;
        }

        public Builder filters(@Nullable List<GetRepositoryDiffsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRepositoryDiffsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isComparisonFromMergeBase Boolean value to indicate whether to use merge base or most recent revision.
         * 
         * @return builder
         * 
         */
        public Builder isComparisonFromMergeBase(@Nullable Boolean isComparisonFromMergeBase) {
            $.isComparisonFromMergeBase = isComparisonFromMergeBase;
            return this;
        }

        /**
         * @param repositoryId Unique repository identifier.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(String repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        /**
         * @param targetRepositoryId The target repository identifier
         * 
         * @return builder
         * 
         */
        public Builder targetRepositoryId(@Nullable String targetRepositoryId) {
            $.targetRepositoryId = targetRepositoryId;
            return this;
        }

        /**
         * @param targetVersion The commit or reference name where changes are coming from.
         * 
         * @return builder
         * 
         */
        public Builder targetVersion(String targetVersion) {
            $.targetVersion = targetVersion;
            return this;
        }

        public GetRepositoryDiffsPlainArgs build() {
            if ($.baseVersion == null) {
                throw new MissingRequiredPropertyException("GetRepositoryDiffsPlainArgs", "baseVersion");
            }
            if ($.repositoryId == null) {
                throw new MissingRequiredPropertyException("GetRepositoryDiffsPlainArgs", "repositoryId");
            }
            if ($.targetVersion == null) {
                throw new MissingRequiredPropertyException("GetRepositoryDiffsPlainArgs", "targetVersion");
            }
            return $;
        }
    }

}
