// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeployArtifactsDeployArtifactCollectionItemDeployArtifactSource {
    /**
     * @return base64 Encoded String
     * 
     */
    private final String base64encodedContent;
    /**
     * @return Specifies the artifact path in the repository.
     * 
     */
    private final String deployArtifactPath;
    /**
     * @return Specifies types of artifact sources.
     * 
     */
    private final String deployArtifactSourceType;
    /**
     * @return Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
     * 
     */
    private final String deployArtifactVersion;
    /**
     * @return Specifies image digest for the version of the image.
     * 
     */
    private final String imageDigest;
    /**
     * @return Specifies OCIR Image Path - optionally include tag.
     * 
     */
    private final String imageUri;
    /**
     * @return The OCID of a repository
     * 
     */
    private final String repositoryId;

    @CustomType.Constructor
    private GetDeployArtifactsDeployArtifactCollectionItemDeployArtifactSource(
        @CustomType.Parameter("base64encodedContent") String base64encodedContent,
        @CustomType.Parameter("deployArtifactPath") String deployArtifactPath,
        @CustomType.Parameter("deployArtifactSourceType") String deployArtifactSourceType,
        @CustomType.Parameter("deployArtifactVersion") String deployArtifactVersion,
        @CustomType.Parameter("imageDigest") String imageDigest,
        @CustomType.Parameter("imageUri") String imageUri,
        @CustomType.Parameter("repositoryId") String repositoryId) {
        this.base64encodedContent = base64encodedContent;
        this.deployArtifactPath = deployArtifactPath;
        this.deployArtifactSourceType = deployArtifactSourceType;
        this.deployArtifactVersion = deployArtifactVersion;
        this.imageDigest = imageDigest;
        this.imageUri = imageUri;
        this.repositoryId = repositoryId;
    }

    /**
     * @return base64 Encoded String
     * 
     */
    public String base64encodedContent() {
        return this.base64encodedContent;
    }
    /**
     * @return Specifies the artifact path in the repository.
     * 
     */
    public String deployArtifactPath() {
        return this.deployArtifactPath;
    }
    /**
     * @return Specifies types of artifact sources.
     * 
     */
    public String deployArtifactSourceType() {
        return this.deployArtifactSourceType;
    }
    /**
     * @return Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
     * 
     */
    public String deployArtifactVersion() {
        return this.deployArtifactVersion;
    }
    /**
     * @return Specifies image digest for the version of the image.
     * 
     */
    public String imageDigest() {
        return this.imageDigest;
    }
    /**
     * @return Specifies OCIR Image Path - optionally include tag.
     * 
     */
    public String imageUri() {
        return this.imageUri;
    }
    /**
     * @return The OCID of a repository
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployArtifactsDeployArtifactCollectionItemDeployArtifactSource defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String base64encodedContent;
        private String deployArtifactPath;
        private String deployArtifactSourceType;
        private String deployArtifactVersion;
        private String imageDigest;
        private String imageUri;
        private String repositoryId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeployArtifactsDeployArtifactCollectionItemDeployArtifactSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.base64encodedContent = defaults.base64encodedContent;
    	      this.deployArtifactPath = defaults.deployArtifactPath;
    	      this.deployArtifactSourceType = defaults.deployArtifactSourceType;
    	      this.deployArtifactVersion = defaults.deployArtifactVersion;
    	      this.imageDigest = defaults.imageDigest;
    	      this.imageUri = defaults.imageUri;
    	      this.repositoryId = defaults.repositoryId;
        }

        public Builder base64encodedContent(String base64encodedContent) {
            this.base64encodedContent = Objects.requireNonNull(base64encodedContent);
            return this;
        }
        public Builder deployArtifactPath(String deployArtifactPath) {
            this.deployArtifactPath = Objects.requireNonNull(deployArtifactPath);
            return this;
        }
        public Builder deployArtifactSourceType(String deployArtifactSourceType) {
            this.deployArtifactSourceType = Objects.requireNonNull(deployArtifactSourceType);
            return this;
        }
        public Builder deployArtifactVersion(String deployArtifactVersion) {
            this.deployArtifactVersion = Objects.requireNonNull(deployArtifactVersion);
            return this;
        }
        public Builder imageDigest(String imageDigest) {
            this.imageDigest = Objects.requireNonNull(imageDigest);
            return this;
        }
        public Builder imageUri(String imageUri) {
            this.imageUri = Objects.requireNonNull(imageUri);
            return this;
        }
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }        public GetDeployArtifactsDeployArtifactCollectionItemDeployArtifactSource build() {
            return new GetDeployArtifactsDeployArtifactCollectionItemDeployArtifactSource(base64encodedContent, deployArtifactPath, deployArtifactSourceType, deployArtifactVersion, imageDigest, imageUri, repositoryId);
        }
    }
}
