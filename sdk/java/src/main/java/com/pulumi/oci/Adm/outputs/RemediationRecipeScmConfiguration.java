// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RemediationRecipeScmConfiguration {
    /**
     * @return (Updatable) The branch used by ADM to patch vulnerabilities.
     * 
     */
    private String branch;
    /**
     * @return (Updatable) The location of the build file relative to the root of the repository. Only Maven build files (POM) are currently supported. If this property is not specified, ADM will use the build file located at the root of the repository.
     * 
     */
    private @Nullable String buildFileLocation;
    /**
     * @return (Updatable) The type of External Source Code Management.
     * 
     */
    private @Nullable String externalScmType;
    /**
     * @return (Updatable) If true, the Pull Request (PR) will be merged after the verify stage completes successfully     If false, the PR with the proposed changes must be reviewed and manually merged.
     * 
     */
    private Boolean isAutomergeEnabled;
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Oracle Cloud Infrastructure DevOps repository.
     * 
     */
    private @Nullable String ociCodeRepositoryId;
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Private Access Token (PAT) Secret. The PAT provides the credentials to access the Jenkins Pipeline.
     * 
     */
    private @Nullable String patSecretId;
    /**
     * @return (Updatable) The location of the repository where the GitHub Actions is defined. For Non-Enterprise GitHub the expected format is https://github.com/[owner]/[repoName] For Enterprise GitHub the expected format is http(s)://[hostname]/api/v3/repos/[owner]/[repoName]
     * 
     */
    private @Nullable String repositoryUrl;
    /**
     * @return (Updatable) The type of Source Code Management.
     * 
     */
    private String scmType;
    /**
     * @return (Updatable) The username that will be used to authenticate with Jenkins.
     * 
     */
    private @Nullable String username;

    private RemediationRecipeScmConfiguration() {}
    /**
     * @return (Updatable) The branch used by ADM to patch vulnerabilities.
     * 
     */
    public String branch() {
        return this.branch;
    }
    /**
     * @return (Updatable) The location of the build file relative to the root of the repository. Only Maven build files (POM) are currently supported. If this property is not specified, ADM will use the build file located at the root of the repository.
     * 
     */
    public Optional<String> buildFileLocation() {
        return Optional.ofNullable(this.buildFileLocation);
    }
    /**
     * @return (Updatable) The type of External Source Code Management.
     * 
     */
    public Optional<String> externalScmType() {
        return Optional.ofNullable(this.externalScmType);
    }
    /**
     * @return (Updatable) If true, the Pull Request (PR) will be merged after the verify stage completes successfully     If false, the PR with the proposed changes must be reviewed and manually merged.
     * 
     */
    public Boolean isAutomergeEnabled() {
        return this.isAutomergeEnabled;
    }
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Oracle Cloud Infrastructure DevOps repository.
     * 
     */
    public Optional<String> ociCodeRepositoryId() {
        return Optional.ofNullable(this.ociCodeRepositoryId);
    }
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Private Access Token (PAT) Secret. The PAT provides the credentials to access the Jenkins Pipeline.
     * 
     */
    public Optional<String> patSecretId() {
        return Optional.ofNullable(this.patSecretId);
    }
    /**
     * @return (Updatable) The location of the repository where the GitHub Actions is defined. For Non-Enterprise GitHub the expected format is https://github.com/[owner]/[repoName] For Enterprise GitHub the expected format is http(s)://[hostname]/api/v3/repos/[owner]/[repoName]
     * 
     */
    public Optional<String> repositoryUrl() {
        return Optional.ofNullable(this.repositoryUrl);
    }
    /**
     * @return (Updatable) The type of Source Code Management.
     * 
     */
    public String scmType() {
        return this.scmType;
    }
    /**
     * @return (Updatable) The username that will be used to authenticate with Jenkins.
     * 
     */
    public Optional<String> username() {
        return Optional.ofNullable(this.username);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RemediationRecipeScmConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String branch;
        private @Nullable String buildFileLocation;
        private @Nullable String externalScmType;
        private Boolean isAutomergeEnabled;
        private @Nullable String ociCodeRepositoryId;
        private @Nullable String patSecretId;
        private @Nullable String repositoryUrl;
        private String scmType;
        private @Nullable String username;
        public Builder() {}
        public Builder(RemediationRecipeScmConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.branch = defaults.branch;
    	      this.buildFileLocation = defaults.buildFileLocation;
    	      this.externalScmType = defaults.externalScmType;
    	      this.isAutomergeEnabled = defaults.isAutomergeEnabled;
    	      this.ociCodeRepositoryId = defaults.ociCodeRepositoryId;
    	      this.patSecretId = defaults.patSecretId;
    	      this.repositoryUrl = defaults.repositoryUrl;
    	      this.scmType = defaults.scmType;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder branch(String branch) {
            this.branch = Objects.requireNonNull(branch);
            return this;
        }
        @CustomType.Setter
        public Builder buildFileLocation(@Nullable String buildFileLocation) {
            this.buildFileLocation = buildFileLocation;
            return this;
        }
        @CustomType.Setter
        public Builder externalScmType(@Nullable String externalScmType) {
            this.externalScmType = externalScmType;
            return this;
        }
        @CustomType.Setter
        public Builder isAutomergeEnabled(Boolean isAutomergeEnabled) {
            this.isAutomergeEnabled = Objects.requireNonNull(isAutomergeEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder ociCodeRepositoryId(@Nullable String ociCodeRepositoryId) {
            this.ociCodeRepositoryId = ociCodeRepositoryId;
            return this;
        }
        @CustomType.Setter
        public Builder patSecretId(@Nullable String patSecretId) {
            this.patSecretId = patSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder repositoryUrl(@Nullable String repositoryUrl) {
            this.repositoryUrl = repositoryUrl;
            return this;
        }
        @CustomType.Setter
        public Builder scmType(String scmType) {
            this.scmType = Objects.requireNonNull(scmType);
            return this;
        }
        @CustomType.Setter
        public Builder username(@Nullable String username) {
            this.username = username;
            return this;
        }
        public RemediationRecipeScmConfiguration build() {
            final var o = new RemediationRecipeScmConfiguration();
            o.branch = branch;
            o.buildFileLocation = buildFileLocation;
            o.externalScmType = externalScmType;
            o.isAutomergeEnabled = isAutomergeEnabled;
            o.ociCodeRepositoryId = ociCodeRepositoryId;
            o.patSecretId = patSecretId;
            o.repositoryUrl = repositoryUrl;
            o.scmType = scmType;
            o.username = username;
            return o;
        }
    }
}