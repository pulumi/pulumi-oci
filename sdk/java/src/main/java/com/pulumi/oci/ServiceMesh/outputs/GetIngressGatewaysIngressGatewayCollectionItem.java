// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewaysIngressGatewayCollectionItemAccessLogging;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewaysIngressGatewayCollectionItemHost;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewaysIngressGatewayCollectionItemMtl;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetIngressGatewaysIngressGatewayCollectionItem {
    /**
     * @return This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    private List<GetIngressGatewaysIngressGatewayCollectionItemAccessLogging> accessLoggings;
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
     * @return Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    private String description;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Array of hostnames and their listener configuration that this gateway will bind to.
     * 
     */
    private List<GetIngressGatewaysIngressGatewayCollectionItemHost> hosts;
    /**
     * @return Unique IngressGateway identifier.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Unique Mesh identifier.
     * 
     */
    private String meshId;
    /**
     * @return Mutual TLS settings used when sending requests to virtual services within the mesh.
     * 
     */
    private List<GetIngressGatewaysIngressGatewayCollectionItemMtl> mtls;
    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    private String name;
    /**
     * @return A filter to return only resources that match the life cycle state given.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time when this resource was created in an RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time when this resource was updated in an RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetIngressGatewaysIngressGatewayCollectionItem() {}
    /**
     * @return This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    public List<GetIngressGatewaysIngressGatewayCollectionItemAccessLogging> accessLoggings() {
        return this.accessLoggings;
    }
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
     * @return Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Array of hostnames and their listener configuration that this gateway will bind to.
     * 
     */
    public List<GetIngressGatewaysIngressGatewayCollectionItemHost> hosts() {
        return this.hosts;
    }
    /**
     * @return Unique IngressGateway identifier.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Unique Mesh identifier.
     * 
     */
    public String meshId() {
        return this.meshId;
    }
    /**
     * @return Mutual TLS settings used when sending requests to virtual services within the mesh.
     * 
     */
    public List<GetIngressGatewaysIngressGatewayCollectionItemMtl> mtls() {
        return this.mtls;
    }
    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return A filter to return only resources that match the life cycle state given.
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
     * @return The time when this resource was created in an RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time when this resource was updated in an RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewaysIngressGatewayCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetIngressGatewaysIngressGatewayCollectionItemAccessLogging> accessLoggings;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private Map<String,Object> freeformTags;
        private List<GetIngressGatewaysIngressGatewayCollectionItemHost> hosts;
        private String id;
        private String lifecycleDetails;
        private String meshId;
        private List<GetIngressGatewaysIngressGatewayCollectionItemMtl> mtls;
        private String name;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetIngressGatewaysIngressGatewayCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLoggings = defaults.accessLoggings;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hosts = defaults.hosts;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.meshId = defaults.meshId;
    	      this.mtls = defaults.mtls;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder accessLoggings(List<GetIngressGatewaysIngressGatewayCollectionItemAccessLogging> accessLoggings) {
            this.accessLoggings = Objects.requireNonNull(accessLoggings);
            return this;
        }
        public Builder accessLoggings(GetIngressGatewaysIngressGatewayCollectionItemAccessLogging... accessLoggings) {
            return accessLoggings(List.of(accessLoggings));
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
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder hosts(List<GetIngressGatewaysIngressGatewayCollectionItemHost> hosts) {
            this.hosts = Objects.requireNonNull(hosts);
            return this;
        }
        public Builder hosts(GetIngressGatewaysIngressGatewayCollectionItemHost... hosts) {
            return hosts(List.of(hosts));
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
        public Builder meshId(String meshId) {
            this.meshId = Objects.requireNonNull(meshId);
            return this;
        }
        @CustomType.Setter
        public Builder mtls(List<GetIngressGatewaysIngressGatewayCollectionItemMtl> mtls) {
            this.mtls = Objects.requireNonNull(mtls);
            return this;
        }
        public Builder mtls(GetIngressGatewaysIngressGatewayCollectionItemMtl... mtls) {
            return mtls(List.of(mtls));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
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
        public GetIngressGatewaysIngressGatewayCollectionItem build() {
            final var o = new GetIngressGatewaysIngressGatewayCollectionItem();
            o.accessLoggings = accessLoggings;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.freeformTags = freeformTags;
            o.hosts = hosts;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.meshId = meshId;
            o.mtls = mtls;
            o.name = name;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}