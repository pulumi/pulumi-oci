// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.inputs.DeployArtifactDeployArtifactSourceHelmVerificationKeySourceArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployArtifactDeployArtifactSourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployArtifactDeployArtifactSourceArgs Empty = new DeployArtifactDeployArtifactSourceArgs();

    /**
     * (Updatable) The Helm commands to be executed, base 64 encoded
     * 
     */
    @Import(name="base64encodedContent")
    private @Nullable Output<String> base64encodedContent;

    /**
     * @return (Updatable) The Helm commands to be executed, base 64 encoded
     * 
     */
    public Optional<Output<String>> base64encodedContent() {
        return Optional.ofNullable(this.base64encodedContent);
    }

    /**
     * (Updatable) The URL of an OCIR repository.
     * 
     */
    @Import(name="chartUrl")
    private @Nullable Output<String> chartUrl;

    /**
     * @return (Updatable) The URL of an OCIR repository.
     * 
     */
    public Optional<Output<String>> chartUrl() {
        return Optional.ofNullable(this.chartUrl);
    }

    /**
     * (Updatable) Specifies the artifact path in the repository.
     * 
     */
    @Import(name="deployArtifactPath")
    private @Nullable Output<String> deployArtifactPath;

    /**
     * @return (Updatable) Specifies the artifact path in the repository.
     * 
     */
    public Optional<Output<String>> deployArtifactPath() {
        return Optional.ofNullable(this.deployArtifactPath);
    }

    /**
     * (Updatable) Specifies types of artifact sources.
     * 
     */
    @Import(name="deployArtifactSourceType", required=true)
    private Output<String> deployArtifactSourceType;

    /**
     * @return (Updatable) Specifies types of artifact sources.
     * 
     */
    public Output<String> deployArtifactSourceType() {
        return this.deployArtifactSourceType;
    }

    /**
     * (Updatable) Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
     * 
     */
    @Import(name="deployArtifactVersion")
    private @Nullable Output<String> deployArtifactVersion;

    /**
     * @return (Updatable) Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
     * 
     */
    public Optional<Output<String>> deployArtifactVersion() {
        return Optional.ofNullable(this.deployArtifactVersion);
    }

    /**
     * (Updatable) Specifies types of artifact sources.
     * 
     */
    @Import(name="helmArtifactSourceType")
    private @Nullable Output<String> helmArtifactSourceType;

    /**
     * @return (Updatable) Specifies types of artifact sources.
     * 
     */
    public Optional<Output<String>> helmArtifactSourceType() {
        return Optional.ofNullable(this.helmArtifactSourceType);
    }

    /**
     * (Updatable) The source of the verification material.
     * 
     */
    @Import(name="helmVerificationKeySource")
    private @Nullable Output<DeployArtifactDeployArtifactSourceHelmVerificationKeySourceArgs> helmVerificationKeySource;

    /**
     * @return (Updatable) The source of the verification material.
     * 
     */
    public Optional<Output<DeployArtifactDeployArtifactSourceHelmVerificationKeySourceArgs>> helmVerificationKeySource() {
        return Optional.ofNullable(this.helmVerificationKeySource);
    }

    /**
     * (Updatable) Specifies image digest for the version of the image.
     * 
     */
    @Import(name="imageDigest")
    private @Nullable Output<String> imageDigest;

    /**
     * @return (Updatable) Specifies image digest for the version of the image.
     * 
     */
    public Optional<Output<String>> imageDigest() {
        return Optional.ofNullable(this.imageDigest);
    }

    /**
     * (Updatable) Specifies OCIR Image Path - optionally include tag.
     * 
     */
    @Import(name="imageUri")
    private @Nullable Output<String> imageUri;

    /**
     * @return (Updatable) Specifies OCIR Image Path - optionally include tag.
     * 
     */
    public Optional<Output<String>> imageUri() {
        return Optional.ofNullable(this.imageUri);
    }

    /**
     * (Updatable) The OCID of a repository
     * 
     */
    @Import(name="repositoryId")
    private @Nullable Output<String> repositoryId;

    /**
     * @return (Updatable) The OCID of a repository
     * 
     */
    public Optional<Output<String>> repositoryId() {
        return Optional.ofNullable(this.repositoryId);
    }

    private DeployArtifactDeployArtifactSourceArgs() {}

    private DeployArtifactDeployArtifactSourceArgs(DeployArtifactDeployArtifactSourceArgs $) {
        this.base64encodedContent = $.base64encodedContent;
        this.chartUrl = $.chartUrl;
        this.deployArtifactPath = $.deployArtifactPath;
        this.deployArtifactSourceType = $.deployArtifactSourceType;
        this.deployArtifactVersion = $.deployArtifactVersion;
        this.helmArtifactSourceType = $.helmArtifactSourceType;
        this.helmVerificationKeySource = $.helmVerificationKeySource;
        this.imageDigest = $.imageDigest;
        this.imageUri = $.imageUri;
        this.repositoryId = $.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployArtifactDeployArtifactSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployArtifactDeployArtifactSourceArgs $;

        public Builder() {
            $ = new DeployArtifactDeployArtifactSourceArgs();
        }

        public Builder(DeployArtifactDeployArtifactSourceArgs defaults) {
            $ = new DeployArtifactDeployArtifactSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param base64encodedContent (Updatable) The Helm commands to be executed, base 64 encoded
         * 
         * @return builder
         * 
         */
        public Builder base64encodedContent(@Nullable Output<String> base64encodedContent) {
            $.base64encodedContent = base64encodedContent;
            return this;
        }

        /**
         * @param base64encodedContent (Updatable) The Helm commands to be executed, base 64 encoded
         * 
         * @return builder
         * 
         */
        public Builder base64encodedContent(String base64encodedContent) {
            return base64encodedContent(Output.of(base64encodedContent));
        }

        /**
         * @param chartUrl (Updatable) The URL of an OCIR repository.
         * 
         * @return builder
         * 
         */
        public Builder chartUrl(@Nullable Output<String> chartUrl) {
            $.chartUrl = chartUrl;
            return this;
        }

        /**
         * @param chartUrl (Updatable) The URL of an OCIR repository.
         * 
         * @return builder
         * 
         */
        public Builder chartUrl(String chartUrl) {
            return chartUrl(Output.of(chartUrl));
        }

        /**
         * @param deployArtifactPath (Updatable) Specifies the artifact path in the repository.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactPath(@Nullable Output<String> deployArtifactPath) {
            $.deployArtifactPath = deployArtifactPath;
            return this;
        }

        /**
         * @param deployArtifactPath (Updatable) Specifies the artifact path in the repository.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactPath(String deployArtifactPath) {
            return deployArtifactPath(Output.of(deployArtifactPath));
        }

        /**
         * @param deployArtifactSourceType (Updatable) Specifies types of artifact sources.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactSourceType(Output<String> deployArtifactSourceType) {
            $.deployArtifactSourceType = deployArtifactSourceType;
            return this;
        }

        /**
         * @param deployArtifactSourceType (Updatable) Specifies types of artifact sources.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactSourceType(String deployArtifactSourceType) {
            return deployArtifactSourceType(Output.of(deployArtifactSourceType));
        }

        /**
         * @param deployArtifactVersion (Updatable) Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactVersion(@Nullable Output<String> deployArtifactVersion) {
            $.deployArtifactVersion = deployArtifactVersion;
            return this;
        }

        /**
         * @param deployArtifactVersion (Updatable) Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactVersion(String deployArtifactVersion) {
            return deployArtifactVersion(Output.of(deployArtifactVersion));
        }

        /**
         * @param helmArtifactSourceType (Updatable) Specifies types of artifact sources.
         * 
         * @return builder
         * 
         */
        public Builder helmArtifactSourceType(@Nullable Output<String> helmArtifactSourceType) {
            $.helmArtifactSourceType = helmArtifactSourceType;
            return this;
        }

        /**
         * @param helmArtifactSourceType (Updatable) Specifies types of artifact sources.
         * 
         * @return builder
         * 
         */
        public Builder helmArtifactSourceType(String helmArtifactSourceType) {
            return helmArtifactSourceType(Output.of(helmArtifactSourceType));
        }

        /**
         * @param helmVerificationKeySource (Updatable) The source of the verification material.
         * 
         * @return builder
         * 
         */
        public Builder helmVerificationKeySource(@Nullable Output<DeployArtifactDeployArtifactSourceHelmVerificationKeySourceArgs> helmVerificationKeySource) {
            $.helmVerificationKeySource = helmVerificationKeySource;
            return this;
        }

        /**
         * @param helmVerificationKeySource (Updatable) The source of the verification material.
         * 
         * @return builder
         * 
         */
        public Builder helmVerificationKeySource(DeployArtifactDeployArtifactSourceHelmVerificationKeySourceArgs helmVerificationKeySource) {
            return helmVerificationKeySource(Output.of(helmVerificationKeySource));
        }

        /**
         * @param imageDigest (Updatable) Specifies image digest for the version of the image.
         * 
         * @return builder
         * 
         */
        public Builder imageDigest(@Nullable Output<String> imageDigest) {
            $.imageDigest = imageDigest;
            return this;
        }

        /**
         * @param imageDigest (Updatable) Specifies image digest for the version of the image.
         * 
         * @return builder
         * 
         */
        public Builder imageDigest(String imageDigest) {
            return imageDigest(Output.of(imageDigest));
        }

        /**
         * @param imageUri (Updatable) Specifies OCIR Image Path - optionally include tag.
         * 
         * @return builder
         * 
         */
        public Builder imageUri(@Nullable Output<String> imageUri) {
            $.imageUri = imageUri;
            return this;
        }

        /**
         * @param imageUri (Updatable) Specifies OCIR Image Path - optionally include tag.
         * 
         * @return builder
         * 
         */
        public Builder imageUri(String imageUri) {
            return imageUri(Output.of(imageUri));
        }

        /**
         * @param repositoryId (Updatable) The OCID of a repository
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(@Nullable Output<String> repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        /**
         * @param repositoryId (Updatable) The OCID of a repository
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(String repositoryId) {
            return repositoryId(Output.of(repositoryId));
        }

        public DeployArtifactDeployArtifactSourceArgs build() {
            if ($.deployArtifactSourceType == null) {
                throw new MissingRequiredPropertyException("DeployArtifactDeployArtifactSourceArgs", "deployArtifactSourceType");
            }
            return $;
        }
    }

}
