// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RemediationRecipeVerifyConfiguration {
    /**
     * @return (Updatable) Additional key-value pairs passed as parameters to the build service when running an experiment.
     * 
     */
    private @Nullable Map<String,Object> additionalParameters;
    /**
     * @return (Updatable) The type of Build Service.
     * 
     */
    private String buildServiceType;
    /**
     * @return (Updatable) The URL that locates the Jenkins pipeline.
     * 
     */
    private @Nullable String jenkinsUrl;
    /**
     * @return (Updatable) The name of the Jenkins pipeline job that identifies the build pipeline.
     * 
     */
    private @Nullable String jobName;
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Private Access Token (PAT) Secret. The PAT provides the credentials to access the Jenkins Pipeline.
     * 
     */
    private @Nullable String patSecretId;
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the user&#39;s DevOps Build Pipeline.
     * 
     */
    private @Nullable String pipelineId;
    /**
     * @return (Updatable) The location of the repository where the GitHub Actions is defined. For Non-Enterprise GitHub the expected format is https://github.com/[owner]/[repoName] For Enterprise GitHub the expected format is http(s)://[hostname]/api/v3/repos/[owner]/[repoName]
     * 
     */
    private @Nullable String repositoryUrl;
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the trigger Secret. The Secret provides access to the trigger for a GitLab pipeline.
     * 
     */
    private @Nullable String triggerSecretId;
    /**
     * @return (Updatable) The username that will be used to authenticate with Jenkins.
     * 
     */
    private @Nullable String username;
    /**
     * @return (Updatable) The name of the GitHub Actions workflow that defines the build pipeline.
     * 
     */
    private @Nullable String workflowName;

    private RemediationRecipeVerifyConfiguration() {}
    /**
     * @return (Updatable) Additional key-value pairs passed as parameters to the build service when running an experiment.
     * 
     */
    public Map<String,Object> additionalParameters() {
        return this.additionalParameters == null ? Map.of() : this.additionalParameters;
    }
    /**
     * @return (Updatable) The type of Build Service.
     * 
     */
    public String buildServiceType() {
        return this.buildServiceType;
    }
    /**
     * @return (Updatable) The URL that locates the Jenkins pipeline.
     * 
     */
    public Optional<String> jenkinsUrl() {
        return Optional.ofNullable(this.jenkinsUrl);
    }
    /**
     * @return (Updatable) The name of the Jenkins pipeline job that identifies the build pipeline.
     * 
     */
    public Optional<String> jobName() {
        return Optional.ofNullable(this.jobName);
    }
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Private Access Token (PAT) Secret. The PAT provides the credentials to access the Jenkins Pipeline.
     * 
     */
    public Optional<String> patSecretId() {
        return Optional.ofNullable(this.patSecretId);
    }
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the user&#39;s DevOps Build Pipeline.
     * 
     */
    public Optional<String> pipelineId() {
        return Optional.ofNullable(this.pipelineId);
    }
    /**
     * @return (Updatable) The location of the repository where the GitHub Actions is defined. For Non-Enterprise GitHub the expected format is https://github.com/[owner]/[repoName] For Enterprise GitHub the expected format is http(s)://[hostname]/api/v3/repos/[owner]/[repoName]
     * 
     */
    public Optional<String> repositoryUrl() {
        return Optional.ofNullable(this.repositoryUrl);
    }
    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the trigger Secret. The Secret provides access to the trigger for a GitLab pipeline.
     * 
     */
    public Optional<String> triggerSecretId() {
        return Optional.ofNullable(this.triggerSecretId);
    }
    /**
     * @return (Updatable) The username that will be used to authenticate with Jenkins.
     * 
     */
    public Optional<String> username() {
        return Optional.ofNullable(this.username);
    }
    /**
     * @return (Updatable) The name of the GitHub Actions workflow that defines the build pipeline.
     * 
     */
    public Optional<String> workflowName() {
        return Optional.ofNullable(this.workflowName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RemediationRecipeVerifyConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,Object> additionalParameters;
        private String buildServiceType;
        private @Nullable String jenkinsUrl;
        private @Nullable String jobName;
        private @Nullable String patSecretId;
        private @Nullable String pipelineId;
        private @Nullable String repositoryUrl;
        private @Nullable String triggerSecretId;
        private @Nullable String username;
        private @Nullable String workflowName;
        public Builder() {}
        public Builder(RemediationRecipeVerifyConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalParameters = defaults.additionalParameters;
    	      this.buildServiceType = defaults.buildServiceType;
    	      this.jenkinsUrl = defaults.jenkinsUrl;
    	      this.jobName = defaults.jobName;
    	      this.patSecretId = defaults.patSecretId;
    	      this.pipelineId = defaults.pipelineId;
    	      this.repositoryUrl = defaults.repositoryUrl;
    	      this.triggerSecretId = defaults.triggerSecretId;
    	      this.username = defaults.username;
    	      this.workflowName = defaults.workflowName;
        }

        @CustomType.Setter
        public Builder additionalParameters(@Nullable Map<String,Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }
        @CustomType.Setter
        public Builder buildServiceType(String buildServiceType) {
            this.buildServiceType = Objects.requireNonNull(buildServiceType);
            return this;
        }
        @CustomType.Setter
        public Builder jenkinsUrl(@Nullable String jenkinsUrl) {
            this.jenkinsUrl = jenkinsUrl;
            return this;
        }
        @CustomType.Setter
        public Builder jobName(@Nullable String jobName) {
            this.jobName = jobName;
            return this;
        }
        @CustomType.Setter
        public Builder patSecretId(@Nullable String patSecretId) {
            this.patSecretId = patSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder pipelineId(@Nullable String pipelineId) {
            this.pipelineId = pipelineId;
            return this;
        }
        @CustomType.Setter
        public Builder repositoryUrl(@Nullable String repositoryUrl) {
            this.repositoryUrl = repositoryUrl;
            return this;
        }
        @CustomType.Setter
        public Builder triggerSecretId(@Nullable String triggerSecretId) {
            this.triggerSecretId = triggerSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder username(@Nullable String username) {
            this.username = username;
            return this;
        }
        @CustomType.Setter
        public Builder workflowName(@Nullable String workflowName) {
            this.workflowName = workflowName;
            return this;
        }
        public RemediationRecipeVerifyConfiguration build() {
            final var o = new RemediationRecipeVerifyConfiguration();
            o.additionalParameters = additionalParameters;
            o.buildServiceType = buildServiceType;
            o.jenkinsUrl = jenkinsUrl;
            o.jobName = jobName;
            o.patSecretId = patSecretId;
            o.pipelineId = pipelineId;
            o.repositoryUrl = repositoryUrl;
            o.triggerSecretId = triggerSecretId;
            o.username = username;
            o.workflowName = workflowName;
            return o;
        }
    }
}