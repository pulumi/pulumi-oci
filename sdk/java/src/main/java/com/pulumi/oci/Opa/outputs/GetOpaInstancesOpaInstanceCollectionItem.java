// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opa.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetOpaInstancesOpaInstanceCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return The entitlement used for billing purposes
     * 
     */
    private String consumptionModel;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Description of the Process Automation instance.
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return unique OpaInstance identifier
     * 
     */
    private String id;
    private String idcsAt;
    /**
     * @return This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    private String identityAppDisplayName;
    /**
     * @return This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    private String identityAppGuid;
    /**
     * @return This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    private String identityAppOpcServiceInstanceGuid;
    /**
     * @return This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    private String identityDomainUrl;
    /**
     * @return OPA Instance URL
     * 
     */
    private String instanceUrl;
    /**
     * @return indicates if breakGlass is enabled for the opa instance.
     * 
     */
    private Boolean isBreakglassEnabled;
    /**
     * @return MeteringType Identifier
     * 
     */
    private String meteringType;
    /**
     * @return Shape of the instance.
     * 
     */
    private String shapeName;
    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time when OpaInstance was created. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the OpaInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;

    private GetOpaInstancesOpaInstanceCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The entitlement used for billing purposes
     * 
     */
    public String consumptionModel() {
        return this.consumptionModel;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description of the Process Automation instance.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
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
     * @return unique OpaInstance identifier
     * 
     */
    public String id() {
        return this.id;
    }
    public String idcsAt() {
        return this.idcsAt;
    }
    /**
     * @return This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    public String identityAppDisplayName() {
        return this.identityAppDisplayName;
    }
    /**
     * @return This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    public String identityAppGuid() {
        return this.identityAppGuid;
    }
    /**
     * @return This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    public String identityAppOpcServiceInstanceGuid() {
        return this.identityAppOpcServiceInstanceGuid;
    }
    /**
     * @return This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     * 
     */
    public String identityDomainUrl() {
        return this.identityDomainUrl;
    }
    /**
     * @return OPA Instance URL
     * 
     */
    public String instanceUrl() {
        return this.instanceUrl;
    }
    /**
     * @return indicates if breakGlass is enabled for the opa instance.
     * 
     */
    public Boolean isBreakglassEnabled() {
        return this.isBreakglassEnabled;
    }
    /**
     * @return MeteringType Identifier
     * 
     */
    public String meteringType() {
        return this.meteringType;
    }
    /**
     * @return Shape of the instance.
     * 
     */
    public String shapeName() {
        return this.shapeName;
    }
    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time when OpaInstance was created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the OpaInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOpaInstancesOpaInstanceCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String consumptionModel;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String idcsAt;
        private String identityAppDisplayName;
        private String identityAppGuid;
        private String identityAppOpcServiceInstanceGuid;
        private String identityDomainUrl;
        private String instanceUrl;
        private Boolean isBreakglassEnabled;
        private String meteringType;
        private String shapeName;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetOpaInstancesOpaInstanceCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.consumptionModel = defaults.consumptionModel;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.idcsAt = defaults.idcsAt;
    	      this.identityAppDisplayName = defaults.identityAppDisplayName;
    	      this.identityAppGuid = defaults.identityAppGuid;
    	      this.identityAppOpcServiceInstanceGuid = defaults.identityAppOpcServiceInstanceGuid;
    	      this.identityDomainUrl = defaults.identityDomainUrl;
    	      this.instanceUrl = defaults.instanceUrl;
    	      this.isBreakglassEnabled = defaults.isBreakglassEnabled;
    	      this.meteringType = defaults.meteringType;
    	      this.shapeName = defaults.shapeName;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder consumptionModel(String consumptionModel) {
            this.consumptionModel = Objects.requireNonNull(consumptionModel);
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
        public Builder idcsAt(String idcsAt) {
            this.idcsAt = Objects.requireNonNull(idcsAt);
            return this;
        }
        @CustomType.Setter
        public Builder identityAppDisplayName(String identityAppDisplayName) {
            this.identityAppDisplayName = Objects.requireNonNull(identityAppDisplayName);
            return this;
        }
        @CustomType.Setter
        public Builder identityAppGuid(String identityAppGuid) {
            this.identityAppGuid = Objects.requireNonNull(identityAppGuid);
            return this;
        }
        @CustomType.Setter
        public Builder identityAppOpcServiceInstanceGuid(String identityAppOpcServiceInstanceGuid) {
            this.identityAppOpcServiceInstanceGuid = Objects.requireNonNull(identityAppOpcServiceInstanceGuid);
            return this;
        }
        @CustomType.Setter
        public Builder identityDomainUrl(String identityDomainUrl) {
            this.identityDomainUrl = Objects.requireNonNull(identityDomainUrl);
            return this;
        }
        @CustomType.Setter
        public Builder instanceUrl(String instanceUrl) {
            this.instanceUrl = Objects.requireNonNull(instanceUrl);
            return this;
        }
        @CustomType.Setter
        public Builder isBreakglassEnabled(Boolean isBreakglassEnabled) {
            this.isBreakglassEnabled = Objects.requireNonNull(isBreakglassEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder meteringType(String meteringType) {
            this.meteringType = Objects.requireNonNull(meteringType);
            return this;
        }
        @CustomType.Setter
        public Builder shapeName(String shapeName) {
            this.shapeName = Objects.requireNonNull(shapeName);
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
        public GetOpaInstancesOpaInstanceCollectionItem build() {
            final var o = new GetOpaInstancesOpaInstanceCollectionItem();
            o.compartmentId = compartmentId;
            o.consumptionModel = consumptionModel;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.idcsAt = idcsAt;
            o.identityAppDisplayName = identityAppDisplayName;
            o.identityAppGuid = identityAppGuid;
            o.identityAppOpcServiceInstanceGuid = identityAppOpcServiceInstanceGuid;
            o.identityDomainUrl = identityDomainUrl;
            o.instanceUrl = instanceUrl;
            o.isBreakglassEnabled = isBreakglassEnabled;
            o.meteringType = meteringType;
            o.shapeName = shapeName;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}