// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobDiscoveryDetailCredential;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobDiscoveryDetailProperty;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobDiscoveryDetailTag;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDiscoveryJobDiscoveryDetail {
    /**
     * @return The OCID of Management Agent
     * 
     */
    private String agentId;
    /**
     * @return List of DiscoveryJOb Credential Details.
     * 
     */
    private List<GetDiscoveryJobDiscoveryDetailCredential> credentials;
    /**
     * @return Property Details
     * 
     */
    private List<GetDiscoveryJobDiscoveryDetailProperty> properties;
    /**
     * @return The Name of resource type
     * 
     */
    private String resourceName;
    /**
     * @return Resource Type.
     * 
     */
    private String resourceType;
    /**
     * @return Property Details
     * 
     */
    private List<GetDiscoveryJobDiscoveryDetailTag> tags;

    private GetDiscoveryJobDiscoveryDetail() {}
    /**
     * @return The OCID of Management Agent
     * 
     */
    public String agentId() {
        return this.agentId;
    }
    /**
     * @return List of DiscoveryJOb Credential Details.
     * 
     */
    public List<GetDiscoveryJobDiscoveryDetailCredential> credentials() {
        return this.credentials;
    }
    /**
     * @return Property Details
     * 
     */
    public List<GetDiscoveryJobDiscoveryDetailProperty> properties() {
        return this.properties;
    }
    /**
     * @return The Name of resource type
     * 
     */
    public String resourceName() {
        return this.resourceName;
    }
    /**
     * @return Resource Type.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return Property Details
     * 
     */
    public List<GetDiscoveryJobDiscoveryDetailTag> tags() {
        return this.tags;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDiscoveryJobDiscoveryDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String agentId;
        private List<GetDiscoveryJobDiscoveryDetailCredential> credentials;
        private List<GetDiscoveryJobDiscoveryDetailProperty> properties;
        private String resourceName;
        private String resourceType;
        private List<GetDiscoveryJobDiscoveryDetailTag> tags;
        public Builder() {}
        public Builder(GetDiscoveryJobDiscoveryDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentId = defaults.agentId;
    	      this.credentials = defaults.credentials;
    	      this.properties = defaults.properties;
    	      this.resourceName = defaults.resourceName;
    	      this.resourceType = defaults.resourceType;
    	      this.tags = defaults.tags;
        }

        @CustomType.Setter
        public Builder agentId(String agentId) {
            this.agentId = Objects.requireNonNull(agentId);
            return this;
        }
        @CustomType.Setter
        public Builder credentials(List<GetDiscoveryJobDiscoveryDetailCredential> credentials) {
            this.credentials = Objects.requireNonNull(credentials);
            return this;
        }
        public Builder credentials(GetDiscoveryJobDiscoveryDetailCredential... credentials) {
            return credentials(List.of(credentials));
        }
        @CustomType.Setter
        public Builder properties(List<GetDiscoveryJobDiscoveryDetailProperty> properties) {
            this.properties = Objects.requireNonNull(properties);
            return this;
        }
        public Builder properties(GetDiscoveryJobDiscoveryDetailProperty... properties) {
            return properties(List.of(properties));
        }
        @CustomType.Setter
        public Builder resourceName(String resourceName) {
            this.resourceName = Objects.requireNonNull(resourceName);
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            this.resourceType = Objects.requireNonNull(resourceType);
            return this;
        }
        @CustomType.Setter
        public Builder tags(List<GetDiscoveryJobDiscoveryDetailTag> tags) {
            this.tags = Objects.requireNonNull(tags);
            return this;
        }
        public Builder tags(GetDiscoveryJobDiscoveryDetailTag... tags) {
            return tags(List.of(tags));
        }
        public GetDiscoveryJobDiscoveryDetail build() {
            final var o = new GetDiscoveryJobDiscoveryDetail();
            o.agentId = agentId;
            o.credentials = credentials;
            o.properties = properties;
            o.resourceName = resourceName;
            o.resourceType = resourceType;
            o.tags = tags;
            return o;
        }
    }
}