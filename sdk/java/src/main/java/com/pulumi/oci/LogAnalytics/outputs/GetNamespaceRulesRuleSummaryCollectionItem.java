// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetNamespaceRulesRuleSummaryCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Description for this resource.
     * 
     */
    private String description;
    /**
     * @return A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The log analytics entity OCID. This ID is a reference used by log analytics features and it represents a resource that is provisioned and managed by the customer on their premises or on the cloud.
     * 
     */
    private String id;
    /**
     * @return A flag indicating whether or not the ingest time rule or scheduled task is enabled.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return The rule kind used for filtering. Only rules of the specified kind will be returned.
     * 
     */
    private String kind;
    /**
     * @return The most recent task execution status.
     * 
     */
    private String lastExecutionStatus;
    /**
     * @return The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     * 
     */
    private String state;
    /**
     * @return The date and time the resource was created, in the format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the scheduled task last executed, in the format defined by RFC3339.
     * 
     */
    private String timeLastExecuted;
    /**
     * @return The date and time the resource was last updated, in the format defined by RFC3339.
     * 
     */
    private String timeUpdated;

    private GetNamespaceRulesRuleSummaryCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description for this resource.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The log analytics entity OCID. This ID is a reference used by log analytics features and it represents a resource that is provisioned and managed by the customer on their premises or on the cloud.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A flag indicating whether or not the ingest time rule or scheduled task is enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The rule kind used for filtering. Only rules of the specified kind will be returned.
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return The most recent task execution status.
     * 
     */
    public String lastExecutionStatus() {
        return this.lastExecutionStatus;
    }
    /**
     * @return The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the resource was created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the scheduled task last executed, in the format defined by RFC3339.
     * 
     */
    public String timeLastExecuted() {
        return this.timeLastExecuted;
    }
    /**
     * @return The date and time the resource was last updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceRulesRuleSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String kind;
        private String lastExecutionStatus;
        private String state;
        private String timeCreated;
        private String timeLastExecuted;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetNamespaceRulesRuleSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.kind = defaults.kind;
    	      this.lastExecutionStatus = defaults.lastExecutionStatus;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastExecuted = defaults.timeLastExecuted;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
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
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            this.kind = Objects.requireNonNull(kind);
            return this;
        }
        @CustomType.Setter
        public Builder lastExecutionStatus(String lastExecutionStatus) {
            this.lastExecutionStatus = Objects.requireNonNull(lastExecutionStatus);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeLastExecuted(String timeLastExecuted) {
            this.timeLastExecuted = Objects.requireNonNull(timeLastExecuted);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetNamespaceRulesRuleSummaryCollectionItem build() {
            final var o = new GetNamespaceRulesRuleSummaryCollectionItem();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isEnabled = isEnabled;
            o.kind = kind;
            o.lastExecutionStatus = lastExecutionStatus;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeLastExecuted = timeLastExecuted;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}