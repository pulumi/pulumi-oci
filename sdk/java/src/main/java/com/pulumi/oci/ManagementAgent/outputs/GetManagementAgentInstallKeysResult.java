// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentInstallKeysFilter;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentInstallKeysManagementAgentInstallKey;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagementAgentInstallKeysResult {
    private @Nullable String accessLevel;
    /**
     * @return Compartment Identifier
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return Management Agent Install Key Name
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetManagementAgentInstallKeysFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of management_agent_install_keys.
     * 
     */
    private List<GetManagementAgentInstallKeysManagementAgentInstallKey> managementAgentInstallKeys;
    /**
     * @return Status of Key
     * 
     */
    private @Nullable String state;

    private GetManagementAgentInstallKeysResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return Compartment Identifier
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return Management Agent Install Key Name
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetManagementAgentInstallKeysFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of management_agent_install_keys.
     * 
     */
    public List<GetManagementAgentInstallKeysManagementAgentInstallKey> managementAgentInstallKeys() {
        return this.managementAgentInstallKeys;
    }
    /**
     * @return Status of Key
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentInstallKeysResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String displayName;
        private @Nullable List<GetManagementAgentInstallKeysFilter> filters;
        private String id;
        private List<GetManagementAgentInstallKeysManagementAgentInstallKey> managementAgentInstallKeys;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetManagementAgentInstallKeysResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managementAgentInstallKeys = defaults.managementAgentInstallKeys;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagementAgentInstallKeysFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagementAgentInstallKeysFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder managementAgentInstallKeys(List<GetManagementAgentInstallKeysManagementAgentInstallKey> managementAgentInstallKeys) {
            this.managementAgentInstallKeys = Objects.requireNonNull(managementAgentInstallKeys);
            return this;
        }
        public Builder managementAgentInstallKeys(GetManagementAgentInstallKeysManagementAgentInstallKey... managementAgentInstallKeys) {
            return managementAgentInstallKeys(List.of(managementAgentInstallKeys));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetManagementAgentInstallKeysResult build() {
            final var o = new GetManagementAgentInstallKeysResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.managementAgentInstallKeys = managementAgentInstallKeys;
            o.state = state;
            return o;
        }
    }
}