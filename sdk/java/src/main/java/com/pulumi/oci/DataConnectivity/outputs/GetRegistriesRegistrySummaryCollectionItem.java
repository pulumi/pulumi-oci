// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetRegistriesRegistrySummaryCollectionItem {
    /**
     * @return The OCID of the compartment containing the resources you want to list.
     * 
     */
    private String compartmentId;
    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Registry description
     * 
     */
    private String description;
    /**
     * @return Data Connectivity Management registry display name; registries can be renamed.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type, or scope. Exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return A unique identifier that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return Lifecycle state of the resource.
     * 
     */
    private String state;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String stateMessage;
    /**
     * @return Time when the Data Connectivity Management registry was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return Time when the Data Connectivity Management registry was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return Name of the user who updated the DCMS registry.
     * 
     */
    private String updatedBy;

    private GetRegistriesRegistrySummaryCollectionItem() {}
    /**
     * @return The OCID of the compartment containing the resources you want to list.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Registry description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Data Connectivity Management registry display name; registries can be renamed.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type, or scope. Exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A unique identifier that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Lifecycle state of the resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String stateMessage() {
        return this.stateMessage;
    }
    /**
     * @return Time when the Data Connectivity Management registry was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time when the Data Connectivity Management registry was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Name of the user who updated the DCMS registry.
     * 
     */
    public String updatedBy() {
        return this.updatedBy;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistriesRegistrySummaryCollectionItem defaults) {
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
        private String state;
        private String stateMessage;
        private String timeCreated;
        private String timeUpdated;
        private String updatedBy;
        public Builder() {}
        public Builder(GetRegistriesRegistrySummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.stateMessage = defaults.stateMessage;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.updatedBy = defaults.updatedBy;
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
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder stateMessage(String stateMessage) {
            this.stateMessage = Objects.requireNonNull(stateMessage);
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
        public Builder updatedBy(String updatedBy) {
            this.updatedBy = Objects.requireNonNull(updatedBy);
            return this;
        }
        public GetRegistriesRegistrySummaryCollectionItem build() {
            final var o = new GetRegistriesRegistrySummaryCollectionItem();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.state = state;
            o.stateMessage = stateMessage;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.updatedBy = updatedBy;
            return o;
        }
    }
}