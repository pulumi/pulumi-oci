// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBuildRunBuildOutputDeliveredArtifactItem {
    /**
     * @return The OCID of the artifact registry repository used by the DeliverArtifactStage
     * 
     */
    private final String artifactRepositoryId;
    /**
     * @return Type of artifact delivered.
     * 
     */
    private final String artifactType;
    /**
     * @return The hash of the container registry artifact pushed by the Deliver Artifacts stage.
     * 
     */
    private final String deliveredArtifactHash;
    /**
     * @return The OCID of the artifact pushed by the Deliver Artifacts stage.
     * 
     */
    private final String deliveredArtifactId;
    /**
     * @return The OCID of the deployment artifact definition.
     * 
     */
    private final String deployArtifactId;
    /**
     * @return The imageUri of the OCIR artifact pushed by the DeliverArtifactStage
     * 
     */
    private final String imageUri;
    /**
     * @return Name of the output artifact defined in the build specification file.
     * 
     */
    private final String outputArtifactName;
    /**
     * @return Path of the repository where artifact was pushed
     * 
     */
    private final String path;
    /**
     * @return Version of the artifact pushed
     * 
     */
    private final String version;

    @CustomType.Constructor
    private GetBuildRunBuildOutputDeliveredArtifactItem(
        @CustomType.Parameter("artifactRepositoryId") String artifactRepositoryId,
        @CustomType.Parameter("artifactType") String artifactType,
        @CustomType.Parameter("deliveredArtifactHash") String deliveredArtifactHash,
        @CustomType.Parameter("deliveredArtifactId") String deliveredArtifactId,
        @CustomType.Parameter("deployArtifactId") String deployArtifactId,
        @CustomType.Parameter("imageUri") String imageUri,
        @CustomType.Parameter("outputArtifactName") String outputArtifactName,
        @CustomType.Parameter("path") String path,
        @CustomType.Parameter("version") String version) {
        this.artifactRepositoryId = artifactRepositoryId;
        this.artifactType = artifactType;
        this.deliveredArtifactHash = deliveredArtifactHash;
        this.deliveredArtifactId = deliveredArtifactId;
        this.deployArtifactId = deployArtifactId;
        this.imageUri = imageUri;
        this.outputArtifactName = outputArtifactName;
        this.path = path;
        this.version = version;
    }

    /**
     * @return The OCID of the artifact registry repository used by the DeliverArtifactStage
     * 
     */
    public String artifactRepositoryId() {
        return this.artifactRepositoryId;
    }
    /**
     * @return Type of artifact delivered.
     * 
     */
    public String artifactType() {
        return this.artifactType;
    }
    /**
     * @return The hash of the container registry artifact pushed by the Deliver Artifacts stage.
     * 
     */
    public String deliveredArtifactHash() {
        return this.deliveredArtifactHash;
    }
    /**
     * @return The OCID of the artifact pushed by the Deliver Artifacts stage.
     * 
     */
    public String deliveredArtifactId() {
        return this.deliveredArtifactId;
    }
    /**
     * @return The OCID of the deployment artifact definition.
     * 
     */
    public String deployArtifactId() {
        return this.deployArtifactId;
    }
    /**
     * @return The imageUri of the OCIR artifact pushed by the DeliverArtifactStage
     * 
     */
    public String imageUri() {
        return this.imageUri;
    }
    /**
     * @return Name of the output artifact defined in the build specification file.
     * 
     */
    public String outputArtifactName() {
        return this.outputArtifactName;
    }
    /**
     * @return Path of the repository where artifact was pushed
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return Version of the artifact pushed
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunBuildOutputDeliveredArtifactItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String artifactRepositoryId;
        private String artifactType;
        private String deliveredArtifactHash;
        private String deliveredArtifactId;
        private String deployArtifactId;
        private String imageUri;
        private String outputArtifactName;
        private String path;
        private String version;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBuildRunBuildOutputDeliveredArtifactItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.artifactRepositoryId = defaults.artifactRepositoryId;
    	      this.artifactType = defaults.artifactType;
    	      this.deliveredArtifactHash = defaults.deliveredArtifactHash;
    	      this.deliveredArtifactId = defaults.deliveredArtifactId;
    	      this.deployArtifactId = defaults.deployArtifactId;
    	      this.imageUri = defaults.imageUri;
    	      this.outputArtifactName = defaults.outputArtifactName;
    	      this.path = defaults.path;
    	      this.version = defaults.version;
        }

        public Builder artifactRepositoryId(String artifactRepositoryId) {
            this.artifactRepositoryId = Objects.requireNonNull(artifactRepositoryId);
            return this;
        }
        public Builder artifactType(String artifactType) {
            this.artifactType = Objects.requireNonNull(artifactType);
            return this;
        }
        public Builder deliveredArtifactHash(String deliveredArtifactHash) {
            this.deliveredArtifactHash = Objects.requireNonNull(deliveredArtifactHash);
            return this;
        }
        public Builder deliveredArtifactId(String deliveredArtifactId) {
            this.deliveredArtifactId = Objects.requireNonNull(deliveredArtifactId);
            return this;
        }
        public Builder deployArtifactId(String deployArtifactId) {
            this.deployArtifactId = Objects.requireNonNull(deployArtifactId);
            return this;
        }
        public Builder imageUri(String imageUri) {
            this.imageUri = Objects.requireNonNull(imageUri);
            return this;
        }
        public Builder outputArtifactName(String outputArtifactName) {
            this.outputArtifactName = Objects.requireNonNull(outputArtifactName);
            return this;
        }
        public Builder path(String path) {
            this.path = Objects.requireNonNull(path);
            return this;
        }
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }        public GetBuildRunBuildOutputDeliveredArtifactItem build() {
            return new GetBuildRunBuildOutputDeliveredArtifactItem(artifactRepositoryId, artifactType, deliveredArtifactHash, deliveredArtifactId, deployArtifactId, imageUri, outputArtifactName, path, version);
        }
    }
}
