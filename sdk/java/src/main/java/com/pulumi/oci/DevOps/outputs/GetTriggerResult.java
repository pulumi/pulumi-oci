// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetTriggerAction;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetTriggerResult {
    /**
     * @return The list of actions that are to be performed for this trigger.
     * 
     */
    private List<GetTriggerAction> actions;
    /**
     * @return The OCID of the compartment that contains the trigger.
     * 
     */
    private String compartmentId;
    private String connectionId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Description about the trigger.
     * 
     */
    private String description;
    /**
     * @return Trigger display name. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The OCID of the DevOps project to which the trigger belongs to.
     * 
     */
    private String projectId;
    /**
     * @return The OCID of the DevOps code repository.
     * 
     */
    private String repositoryId;
    /**
     * @return The current state of the trigger.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the trigger was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private String timeCreated;
    /**
     * @return The time the trigger was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private String timeUpdated;
    private String triggerId;
    /**
     * @return Source of the trigger. Allowed values are, GITHUB and GITLAB.
     * 
     */
    private String triggerSource;
    /**
     * @return The endpoint that listens to trigger events.
     * 
     */
    private String triggerUrl;

    private GetTriggerResult() {}
    /**
     * @return The list of actions that are to be performed for this trigger.
     * 
     */
    public List<GetTriggerAction> actions() {
        return this.actions;
    }
    /**
     * @return The OCID of the compartment that contains the trigger.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public String connectionId() {
        return this.connectionId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description about the trigger.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Trigger display name. Avoid entering confidential information.
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
     * @return The OCID of the DevOps project to which the trigger belongs to.
     * 
     */
    public String projectId() {
        return this.projectId;
    }
    /**
     * @return The OCID of the DevOps code repository.
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }
    /**
     * @return The current state of the trigger.
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
     * @return The time the trigger was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the trigger was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    public String triggerId() {
        return this.triggerId;
    }
    /**
     * @return Source of the trigger. Allowed values are, GITHUB and GITLAB.
     * 
     */
    public String triggerSource() {
        return this.triggerSource;
    }
    /**
     * @return The endpoint that listens to trigger events.
     * 
     */
    public String triggerUrl() {
        return this.triggerUrl;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTriggerResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetTriggerAction> actions;
        private String compartmentId;
        private String connectionId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String projectId;
        private String repositoryId;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String triggerId;
        private String triggerSource;
        private String triggerUrl;
        public Builder() {}
        public Builder(GetTriggerResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionId = defaults.connectionId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.projectId = defaults.projectId;
    	      this.repositoryId = defaults.repositoryId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.triggerId = defaults.triggerId;
    	      this.triggerSource = defaults.triggerSource;
    	      this.triggerUrl = defaults.triggerUrl;
        }

        @CustomType.Setter
        public Builder actions(List<GetTriggerAction> actions) {
            this.actions = Objects.requireNonNull(actions);
            return this;
        }
        public Builder actions(GetTriggerAction... actions) {
            return actions(List.of(actions));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder connectionId(String connectionId) {
            this.connectionId = Objects.requireNonNull(connectionId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder projectId(String projectId) {
            this.projectId = Objects.requireNonNull(projectId);
            return this;
        }
        @CustomType.Setter
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder triggerId(String triggerId) {
            this.triggerId = Objects.requireNonNull(triggerId);
            return this;
        }
        @CustomType.Setter
        public Builder triggerSource(String triggerSource) {
            this.triggerSource = Objects.requireNonNull(triggerSource);
            return this;
        }
        @CustomType.Setter
        public Builder triggerUrl(String triggerUrl) {
            this.triggerUrl = Objects.requireNonNull(triggerUrl);
            return this;
        }
        public GetTriggerResult build() {
            final var o = new GetTriggerResult();
            o.actions = actions;
            o.compartmentId = compartmentId;
            o.connectionId = connectionId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.projectId = projectId;
            o.repositoryId = repositoryId;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.triggerId = triggerId;
            o.triggerSource = triggerSource;
            o.triggerUrl = triggerUrl;
            return o;
        }
    }
}