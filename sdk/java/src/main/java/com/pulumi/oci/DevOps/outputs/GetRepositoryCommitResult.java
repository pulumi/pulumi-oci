// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRepositoryCommitResult {
    /**
     * @return Email of the author of the repository.
     * 
     */
    private final String authorEmail;
    /**
     * @return Name of the author of the repository.
     * 
     */
    private final String authorName;
    /**
     * @return Commit hash pointed to by reference name.
     * 
     */
    private final String commitId;
    /**
     * @return The commit message.
     * 
     */
    private final String commitMessage;
    /**
     * @return Email of who creates the commit.
     * 
     */
    private final String committerEmail;
    /**
     * @return Name of who creates the commit.
     * 
     */
    private final String committerName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return An array of parent commit IDs of created commit.
     * 
     */
    private final List<String> parentCommitIds;
    private final String repositoryId;
    /**
     * @return The time at which commit was created.
     * 
     */
    private final String timeCreated;
    /**
     * @return Tree information for the specified commit.
     * 
     */
    private final String treeId;

    @CustomType.Constructor
    private GetRepositoryCommitResult(
        @CustomType.Parameter("authorEmail") String authorEmail,
        @CustomType.Parameter("authorName") String authorName,
        @CustomType.Parameter("commitId") String commitId,
        @CustomType.Parameter("commitMessage") String commitMessage,
        @CustomType.Parameter("committerEmail") String committerEmail,
        @CustomType.Parameter("committerName") String committerName,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("parentCommitIds") List<String> parentCommitIds,
        @CustomType.Parameter("repositoryId") String repositoryId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("treeId") String treeId) {
        this.authorEmail = authorEmail;
        this.authorName = authorName;
        this.commitId = commitId;
        this.commitMessage = commitMessage;
        this.committerEmail = committerEmail;
        this.committerName = committerName;
        this.id = id;
        this.parentCommitIds = parentCommitIds;
        this.repositoryId = repositoryId;
        this.timeCreated = timeCreated;
        this.treeId = treeId;
    }

    /**
     * @return Email of the author of the repository.
     * 
     */
    public String authorEmail() {
        return this.authorEmail;
    }
    /**
     * @return Name of the author of the repository.
     * 
     */
    public String authorName() {
        return this.authorName;
    }
    /**
     * @return Commit hash pointed to by reference name.
     * 
     */
    public String commitId() {
        return this.commitId;
    }
    /**
     * @return The commit message.
     * 
     */
    public String commitMessage() {
        return this.commitMessage;
    }
    /**
     * @return Email of who creates the commit.
     * 
     */
    public String committerEmail() {
        return this.committerEmail;
    }
    /**
     * @return Name of who creates the commit.
     * 
     */
    public String committerName() {
        return this.committerName;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An array of parent commit IDs of created commit.
     * 
     */
    public List<String> parentCommitIds() {
        return this.parentCommitIds;
    }
    public String repositoryId() {
        return this.repositoryId;
    }
    /**
     * @return The time at which commit was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Tree information for the specified commit.
     * 
     */
    public String treeId() {
        return this.treeId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoryCommitResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String authorEmail;
        private String authorName;
        private String commitId;
        private String commitMessage;
        private String committerEmail;
        private String committerName;
        private String id;
        private List<String> parentCommitIds;
        private String repositoryId;
        private String timeCreated;
        private String treeId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRepositoryCommitResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authorEmail = defaults.authorEmail;
    	      this.authorName = defaults.authorName;
    	      this.commitId = defaults.commitId;
    	      this.commitMessage = defaults.commitMessage;
    	      this.committerEmail = defaults.committerEmail;
    	      this.committerName = defaults.committerName;
    	      this.id = defaults.id;
    	      this.parentCommitIds = defaults.parentCommitIds;
    	      this.repositoryId = defaults.repositoryId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.treeId = defaults.treeId;
        }

        public Builder authorEmail(String authorEmail) {
            this.authorEmail = Objects.requireNonNull(authorEmail);
            return this;
        }
        public Builder authorName(String authorName) {
            this.authorName = Objects.requireNonNull(authorName);
            return this;
        }
        public Builder commitId(String commitId) {
            this.commitId = Objects.requireNonNull(commitId);
            return this;
        }
        public Builder commitMessage(String commitMessage) {
            this.commitMessage = Objects.requireNonNull(commitMessage);
            return this;
        }
        public Builder committerEmail(String committerEmail) {
            this.committerEmail = Objects.requireNonNull(committerEmail);
            return this;
        }
        public Builder committerName(String committerName) {
            this.committerName = Objects.requireNonNull(committerName);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder parentCommitIds(List<String> parentCommitIds) {
            this.parentCommitIds = Objects.requireNonNull(parentCommitIds);
            return this;
        }
        public Builder parentCommitIds(String... parentCommitIds) {
            return parentCommitIds(List.of(parentCommitIds));
        }
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder treeId(String treeId) {
            this.treeId = Objects.requireNonNull(treeId);
            return this;
        }        public GetRepositoryCommitResult build() {
            return new GetRepositoryCommitResult(authorEmail, authorName, commitId, commitMessage, committerEmail, committerName, id, parentCommitIds, repositoryId, timeCreated, treeId);
        }
    }
}
