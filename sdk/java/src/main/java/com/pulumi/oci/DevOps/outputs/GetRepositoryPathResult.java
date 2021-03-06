// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetRepositoryPathItem;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRepositoryPathResult {
    private final @Nullable String displayName;
    private final @Nullable String folderPath;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return List of objects describing files or directories in a repository.
     * 
     */
    private final List<GetRepositoryPathItem> items;
    private final @Nullable Boolean pathsInSubtree;
    private final @Nullable String ref;
    private final String repositoryId;

    @CustomType.Constructor
    private GetRepositoryPathResult(
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("folderPath") @Nullable String folderPath,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("items") List<GetRepositoryPathItem> items,
        @CustomType.Parameter("pathsInSubtree") @Nullable Boolean pathsInSubtree,
        @CustomType.Parameter("ref") @Nullable String ref,
        @CustomType.Parameter("repositoryId") String repositoryId) {
        this.displayName = displayName;
        this.folderPath = folderPath;
        this.id = id;
        this.items = items;
        this.pathsInSubtree = pathsInSubtree;
        this.ref = ref;
        this.repositoryId = repositoryId;
    }

    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public Optional<String> folderPath() {
        return Optional.ofNullable(this.folderPath);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return List of objects describing files or directories in a repository.
     * 
     */
    public List<GetRepositoryPathItem> items() {
        return this.items;
    }
    public Optional<Boolean> pathsInSubtree() {
        return Optional.ofNullable(this.pathsInSubtree);
    }
    public Optional<String> ref() {
        return Optional.ofNullable(this.ref);
    }
    public String repositoryId() {
        return this.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoryPathResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable String folderPath;
        private String id;
        private List<GetRepositoryPathItem> items;
        private @Nullable Boolean pathsInSubtree;
        private @Nullable String ref;
        private String repositoryId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRepositoryPathResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.folderPath = defaults.folderPath;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.pathsInSubtree = defaults.pathsInSubtree;
    	      this.ref = defaults.ref;
    	      this.repositoryId = defaults.repositoryId;
        }

        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder folderPath(@Nullable String folderPath) {
            this.folderPath = folderPath;
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder items(List<GetRepositoryPathItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetRepositoryPathItem... items) {
            return items(List.of(items));
        }
        public Builder pathsInSubtree(@Nullable Boolean pathsInSubtree) {
            this.pathsInSubtree = pathsInSubtree;
            return this;
        }
        public Builder ref(@Nullable String ref) {
            this.ref = ref;
            return this;
        }
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }        public GetRepositoryPathResult build() {
            return new GetRepositoryPathResult(displayName, folderPath, id, items, pathsInSubtree, ref, repositoryId);
        }
    }
}
