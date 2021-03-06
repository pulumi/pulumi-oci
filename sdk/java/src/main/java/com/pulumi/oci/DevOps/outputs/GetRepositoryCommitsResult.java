// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetRepositoryCommitsFilter;
import com.pulumi.oci.DevOps.outputs.GetRepositoryCommitsRepositoryCommitCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRepositoryCommitsResult {
    /**
     * @return Name of the author of the repository.
     * 
     */
    private final @Nullable String authorName;
    /**
     * @return The commit message.
     * 
     */
    private final @Nullable String commitMessage;
    private final @Nullable String excludeRefName;
    private final @Nullable String filePath;
    private final @Nullable List<GetRepositoryCommitsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final @Nullable String refName;
    /**
     * @return The list of repository_commit_collection.
     * 
     */
    private final List<GetRepositoryCommitsRepositoryCommitCollection> repositoryCommitCollections;
    private final String repositoryId;
    private final @Nullable String timestampGreaterThanOrEqualTo;
    private final @Nullable String timestampLessThanOrEqualTo;

    @CustomType.Constructor
    private GetRepositoryCommitsResult(
        @CustomType.Parameter("authorName") @Nullable String authorName,
        @CustomType.Parameter("commitMessage") @Nullable String commitMessage,
        @CustomType.Parameter("excludeRefName") @Nullable String excludeRefName,
        @CustomType.Parameter("filePath") @Nullable String filePath,
        @CustomType.Parameter("filters") @Nullable List<GetRepositoryCommitsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("refName") @Nullable String refName,
        @CustomType.Parameter("repositoryCommitCollections") List<GetRepositoryCommitsRepositoryCommitCollection> repositoryCommitCollections,
        @CustomType.Parameter("repositoryId") String repositoryId,
        @CustomType.Parameter("timestampGreaterThanOrEqualTo") @Nullable String timestampGreaterThanOrEqualTo,
        @CustomType.Parameter("timestampLessThanOrEqualTo") @Nullable String timestampLessThanOrEqualTo) {
        this.authorName = authorName;
        this.commitMessage = commitMessage;
        this.excludeRefName = excludeRefName;
        this.filePath = filePath;
        this.filters = filters;
        this.id = id;
        this.refName = refName;
        this.repositoryCommitCollections = repositoryCommitCollections;
        this.repositoryId = repositoryId;
        this.timestampGreaterThanOrEqualTo = timestampGreaterThanOrEqualTo;
        this.timestampLessThanOrEqualTo = timestampLessThanOrEqualTo;
    }

    /**
     * @return Name of the author of the repository.
     * 
     */
    public Optional<String> authorName() {
        return Optional.ofNullable(this.authorName);
    }
    /**
     * @return The commit message.
     * 
     */
    public Optional<String> commitMessage() {
        return Optional.ofNullable(this.commitMessage);
    }
    public Optional<String> excludeRefName() {
        return Optional.ofNullable(this.excludeRefName);
    }
    public Optional<String> filePath() {
        return Optional.ofNullable(this.filePath);
    }
    public List<GetRepositoryCommitsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> refName() {
        return Optional.ofNullable(this.refName);
    }
    /**
     * @return The list of repository_commit_collection.
     * 
     */
    public List<GetRepositoryCommitsRepositoryCommitCollection> repositoryCommitCollections() {
        return this.repositoryCommitCollections;
    }
    public String repositoryId() {
        return this.repositoryId;
    }
    public Optional<String> timestampGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timestampGreaterThanOrEqualTo);
    }
    public Optional<String> timestampLessThanOrEqualTo() {
        return Optional.ofNullable(this.timestampLessThanOrEqualTo);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoryCommitsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String authorName;
        private @Nullable String commitMessage;
        private @Nullable String excludeRefName;
        private @Nullable String filePath;
        private @Nullable List<GetRepositoryCommitsFilter> filters;
        private String id;
        private @Nullable String refName;
        private List<GetRepositoryCommitsRepositoryCommitCollection> repositoryCommitCollections;
        private String repositoryId;
        private @Nullable String timestampGreaterThanOrEqualTo;
        private @Nullable String timestampLessThanOrEqualTo;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRepositoryCommitsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authorName = defaults.authorName;
    	      this.commitMessage = defaults.commitMessage;
    	      this.excludeRefName = defaults.excludeRefName;
    	      this.filePath = defaults.filePath;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.refName = defaults.refName;
    	      this.repositoryCommitCollections = defaults.repositoryCommitCollections;
    	      this.repositoryId = defaults.repositoryId;
    	      this.timestampGreaterThanOrEqualTo = defaults.timestampGreaterThanOrEqualTo;
    	      this.timestampLessThanOrEqualTo = defaults.timestampLessThanOrEqualTo;
        }

        public Builder authorName(@Nullable String authorName) {
            this.authorName = authorName;
            return this;
        }
        public Builder commitMessage(@Nullable String commitMessage) {
            this.commitMessage = commitMessage;
            return this;
        }
        public Builder excludeRefName(@Nullable String excludeRefName) {
            this.excludeRefName = excludeRefName;
            return this;
        }
        public Builder filePath(@Nullable String filePath) {
            this.filePath = filePath;
            return this;
        }
        public Builder filters(@Nullable List<GetRepositoryCommitsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetRepositoryCommitsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder refName(@Nullable String refName) {
            this.refName = refName;
            return this;
        }
        public Builder repositoryCommitCollections(List<GetRepositoryCommitsRepositoryCommitCollection> repositoryCommitCollections) {
            this.repositoryCommitCollections = Objects.requireNonNull(repositoryCommitCollections);
            return this;
        }
        public Builder repositoryCommitCollections(GetRepositoryCommitsRepositoryCommitCollection... repositoryCommitCollections) {
            return repositoryCommitCollections(List.of(repositoryCommitCollections));
        }
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }
        public Builder timestampGreaterThanOrEqualTo(@Nullable String timestampGreaterThanOrEqualTo) {
            this.timestampGreaterThanOrEqualTo = timestampGreaterThanOrEqualTo;
            return this;
        }
        public Builder timestampLessThanOrEqualTo(@Nullable String timestampLessThanOrEqualTo) {
            this.timestampLessThanOrEqualTo = timestampLessThanOrEqualTo;
            return this;
        }        public GetRepositoryCommitsResult build() {
            return new GetRepositoryCommitsResult(authorName, commitMessage, excludeRefName, filePath, filters, id, refName, repositoryCommitCollections, repositoryId, timestampGreaterThanOrEqualTo, timestampLessThanOrEqualTo);
        }
    }
}
