// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRepositoryObjectResult {
    private final @Nullable String filePath;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return Flag to determine if the object contains binary file content or not.
     * 
     */
    private final Boolean isBinary;
    private final @Nullable String refName;
    private final String repositoryId;
    /**
     * @return SHA-1 hash of git object.
     * 
     */
    private final String sha;
    /**
     * @return Size in bytes.
     * 
     */
    private final String sizeInBytes;
    /**
     * @return The type of git object.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetRepositoryObjectResult(
        @CustomType.Parameter("filePath") @Nullable String filePath,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isBinary") Boolean isBinary,
        @CustomType.Parameter("refName") @Nullable String refName,
        @CustomType.Parameter("repositoryId") String repositoryId,
        @CustomType.Parameter("sha") String sha,
        @CustomType.Parameter("sizeInBytes") String sizeInBytes,
        @CustomType.Parameter("type") String type) {
        this.filePath = filePath;
        this.id = id;
        this.isBinary = isBinary;
        this.refName = refName;
        this.repositoryId = repositoryId;
        this.sha = sha;
        this.sizeInBytes = sizeInBytes;
        this.type = type;
    }

    public Optional<String> filePath() {
        return Optional.ofNullable(this.filePath);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Flag to determine if the object contains binary file content or not.
     * 
     */
    public Boolean isBinary() {
        return this.isBinary;
    }
    public Optional<String> refName() {
        return Optional.ofNullable(this.refName);
    }
    public String repositoryId() {
        return this.repositoryId;
    }
    /**
     * @return SHA-1 hash of git object.
     * 
     */
    public String sha() {
        return this.sha;
    }
    /**
     * @return Size in bytes.
     * 
     */
    public String sizeInBytes() {
        return this.sizeInBytes;
    }
    /**
     * @return The type of git object.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoryObjectResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String filePath;
        private String id;
        private Boolean isBinary;
        private @Nullable String refName;
        private String repositoryId;
        private String sha;
        private String sizeInBytes;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRepositoryObjectResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filePath = defaults.filePath;
    	      this.id = defaults.id;
    	      this.isBinary = defaults.isBinary;
    	      this.refName = defaults.refName;
    	      this.repositoryId = defaults.repositoryId;
    	      this.sha = defaults.sha;
    	      this.sizeInBytes = defaults.sizeInBytes;
    	      this.type = defaults.type;
        }

        public Builder filePath(@Nullable String filePath) {
            this.filePath = filePath;
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isBinary(Boolean isBinary) {
            this.isBinary = Objects.requireNonNull(isBinary);
            return this;
        }
        public Builder refName(@Nullable String refName) {
            this.refName = refName;
            return this;
        }
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }
        public Builder sha(String sha) {
            this.sha = Objects.requireNonNull(sha);
            return this;
        }
        public Builder sizeInBytes(String sizeInBytes) {
            this.sizeInBytes = Objects.requireNonNull(sizeInBytes);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetRepositoryObjectResult build() {
            return new GetRepositoryObjectResult(filePath, id, isBinary, refName, repositoryId, sha, sizeInBytes, type);
        }
    }
}
