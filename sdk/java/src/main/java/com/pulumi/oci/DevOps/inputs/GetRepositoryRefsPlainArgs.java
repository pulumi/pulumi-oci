// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.GetRepositoryRefsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepositoryRefsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepositoryRefsPlainArgs Empty = new GetRepositoryRefsPlainArgs();

    /**
     * Commit ID in a repository.
     * 
     */
    @Import(name="commitId")
    private @Nullable String commitId;

    /**
     * @return Commit ID in a repository.
     * 
     */
    public Optional<String> commitId() {
        return Optional.ofNullable(this.commitId);
    }

    @Import(name="filters")
    private @Nullable List<GetRepositoryRefsFilter> filters;

    public Optional<List<GetRepositoryRefsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given reference name.
     * 
     */
    @Import(name="refName")
    private @Nullable String refName;

    /**
     * @return A filter to return only resources that match the given reference name.
     * 
     */
    public Optional<String> refName() {
        return Optional.ofNullable(this.refName);
    }

    /**
     * Reference type to distinguish between branch and tag. If it is not specified, all references are returned.
     * 
     */
    @Import(name="refType")
    private @Nullable String refType;

    /**
     * @return Reference type to distinguish between branch and tag. If it is not specified, all references are returned.
     * 
     */
    public Optional<String> refType() {
        return Optional.ofNullable(this.refType);
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

    private GetRepositoryRefsPlainArgs() {}

    private GetRepositoryRefsPlainArgs(GetRepositoryRefsPlainArgs $) {
        this.commitId = $.commitId;
        this.filters = $.filters;
        this.refName = $.refName;
        this.refType = $.refType;
        this.repositoryId = $.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepositoryRefsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepositoryRefsPlainArgs $;

        public Builder() {
            $ = new GetRepositoryRefsPlainArgs();
        }

        public Builder(GetRepositoryRefsPlainArgs defaults) {
            $ = new GetRepositoryRefsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param commitId Commit ID in a repository.
         * 
         * @return builder
         * 
         */
        public Builder commitId(@Nullable String commitId) {
            $.commitId = commitId;
            return this;
        }

        public Builder filters(@Nullable List<GetRepositoryRefsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRepositoryRefsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param refName A filter to return only resources that match the given reference name.
         * 
         * @return builder
         * 
         */
        public Builder refName(@Nullable String refName) {
            $.refName = refName;
            return this;
        }

        /**
         * @param refType Reference type to distinguish between branch and tag. If it is not specified, all references are returned.
         * 
         * @return builder
         * 
         */
        public Builder refType(@Nullable String refType) {
            $.refType = refType;
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

        public GetRepositoryRefsPlainArgs build() {
            $.repositoryId = Objects.requireNonNull($.repositoryId, "expected parameter 'repositoryId' to be non-null");
            return $;
        }
    }

}