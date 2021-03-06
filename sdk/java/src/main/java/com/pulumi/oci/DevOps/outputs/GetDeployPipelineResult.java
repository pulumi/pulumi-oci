// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelineDeployPipelineArtifact;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelineDeployPipelineEnvironment;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelineDeployPipelineParameter;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDeployPipelineResult {
    /**
     * @return The OCID of the compartment where the pipeline is created.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return List of all artifacts used in the pipeline.
     * 
     */
    private final List<GetDeployPipelineDeployPipelineArtifact> deployPipelineArtifacts;
    /**
     * @return List of all environments used in the pipeline.
     * 
     */
    private final List<GetDeployPipelineDeployPipelineEnvironment> deployPipelineEnvironments;
    private final String deployPipelineId;
    /**
     * @return Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
     * 
     */
    private final List<GetDeployPipelineDeployPipelineParameter> deployPipelineParameters;
    /**
     * @return Optional description about the deployment pipeline.
     * 
     */
    private final String description;
    /**
     * @return Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private final String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return The OCID of a project.
     * 
     */
    private final String projectId;
    /**
     * @return The current state of the deployment pipeline.
     * 
     */
    private final String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private final Map<String,Object> systemTags;
    /**
     * @return Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private final String timeCreated;
    /**
     * @return Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetDeployPipelineResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("deployPipelineArtifacts") List<GetDeployPipelineDeployPipelineArtifact> deployPipelineArtifacts,
        @CustomType.Parameter("deployPipelineEnvironments") List<GetDeployPipelineDeployPipelineEnvironment> deployPipelineEnvironments,
        @CustomType.Parameter("deployPipelineId") String deployPipelineId,
        @CustomType.Parameter("deployPipelineParameters") List<GetDeployPipelineDeployPipelineParameter> deployPipelineParameters,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("projectId") String projectId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("systemTags") Map<String,Object> systemTags,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.deployPipelineArtifacts = deployPipelineArtifacts;
        this.deployPipelineEnvironments = deployPipelineEnvironments;
        this.deployPipelineId = deployPipelineId;
        this.deployPipelineParameters = deployPipelineParameters;
        this.description = description;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.lifecycleDetails = lifecycleDetails;
        this.projectId = projectId;
        this.state = state;
        this.systemTags = systemTags;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return The OCID of the compartment where the pipeline is created.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return List of all artifacts used in the pipeline.
     * 
     */
    public List<GetDeployPipelineDeployPipelineArtifact> deployPipelineArtifacts() {
        return this.deployPipelineArtifacts;
    }
    /**
     * @return List of all environments used in the pipeline.
     * 
     */
    public List<GetDeployPipelineDeployPipelineEnvironment> deployPipelineEnvironments() {
        return this.deployPipelineEnvironments;
    }
    public String deployPipelineId() {
        return this.deployPipelineId;
    }
    /**
     * @return Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
     * 
     */
    public List<GetDeployPipelineDeployPipelineParameter> deployPipelineParameters() {
        return this.deployPipelineParameters;
    }
    /**
     * @return Optional description about the deployment pipeline.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The OCID of a project.
     * 
     */
    public String projectId() {
        return this.projectId;
    }
    /**
     * @return The current state of the deployment pipeline.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelineResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private List<GetDeployPipelineDeployPipelineArtifact> deployPipelineArtifacts;
        private List<GetDeployPipelineDeployPipelineEnvironment> deployPipelineEnvironments;
        private String deployPipelineId;
        private List<GetDeployPipelineDeployPipelineParameter> deployPipelineParameters;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String projectId;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeployPipelineResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.deployPipelineArtifacts = defaults.deployPipelineArtifacts;
    	      this.deployPipelineEnvironments = defaults.deployPipelineEnvironments;
    	      this.deployPipelineId = defaults.deployPipelineId;
    	      this.deployPipelineParameters = defaults.deployPipelineParameters;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder deployPipelineArtifacts(List<GetDeployPipelineDeployPipelineArtifact> deployPipelineArtifacts) {
            this.deployPipelineArtifacts = Objects.requireNonNull(deployPipelineArtifacts);
            return this;
        }
        public Builder deployPipelineArtifacts(GetDeployPipelineDeployPipelineArtifact... deployPipelineArtifacts) {
            return deployPipelineArtifacts(List.of(deployPipelineArtifacts));
        }
        public Builder deployPipelineEnvironments(List<GetDeployPipelineDeployPipelineEnvironment> deployPipelineEnvironments) {
            this.deployPipelineEnvironments = Objects.requireNonNull(deployPipelineEnvironments);
            return this;
        }
        public Builder deployPipelineEnvironments(GetDeployPipelineDeployPipelineEnvironment... deployPipelineEnvironments) {
            return deployPipelineEnvironments(List.of(deployPipelineEnvironments));
        }
        public Builder deployPipelineId(String deployPipelineId) {
            this.deployPipelineId = Objects.requireNonNull(deployPipelineId);
            return this;
        }
        public Builder deployPipelineParameters(List<GetDeployPipelineDeployPipelineParameter> deployPipelineParameters) {
            this.deployPipelineParameters = Objects.requireNonNull(deployPipelineParameters);
            return this;
        }
        public Builder deployPipelineParameters(GetDeployPipelineDeployPipelineParameter... deployPipelineParameters) {
            return deployPipelineParameters(List.of(deployPipelineParameters));
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder projectId(String projectId) {
            this.projectId = Objects.requireNonNull(projectId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetDeployPipelineResult build() {
            return new GetDeployPipelineResult(compartmentId, definedTags, deployPipelineArtifacts, deployPipelineEnvironments, deployPipelineId, deployPipelineParameters, description, displayName, freeformTags, id, lifecycleDetails, projectId, state, systemTags, timeCreated, timeUpdated);
        }
    }
}
