// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPrivateEndpointsDataSciencePrivateEndpoint {
    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    private String createdBy;
    /**
     * @return Resource types in the Data Science service such as notebooks.
     * 
     */
    private String dataScienceResourceType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user friendly description. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    private String displayName;
    /**
     * @return Accesing the Data Science resource using FQDN.
     * 
     */
    private String fqdn;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of a private endpoint.
     * 
     */
    private String id;
    /**
     * @return Details of the state of Data Science private endpoint.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return An array of network security group OCIDs.
     * 
     */
    private List<String> nsgIds;
    /**
     * @return The lifecycle state of the private endpoint.
     * 
     */
    private String state;
    private String subDomain;
    /**
     * @return The OCID of a subnet.
     * 
     */
    private String subnetId;
    /**
     * @return The date and time that the Data Science private endpoint was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time that the Data Science private endpoint was updated expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetPrivateEndpointsDataSciencePrivateEndpoint() {}
    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return Resource types in the Data Science service such as notebooks.
     * 
     */
    public String dataScienceResourceType() {
        return this.dataScienceResourceType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user friendly description. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Accesing the Data Science resource using FQDN.
     * 
     */
    public String fqdn() {
        return this.fqdn;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of a private endpoint.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details of the state of Data Science private endpoint.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return An array of network security group OCIDs.
     * 
     */
    public List<String> nsgIds() {
        return this.nsgIds;
    }
    /**
     * @return The lifecycle state of the private endpoint.
     * 
     */
    public String state() {
        return this.state;
    }
    public String subDomain() {
        return this.subDomain;
    }
    /**
     * @return The OCID of a subnet.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The date and time that the Data Science private endpoint was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the Data Science private endpoint was updated expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateEndpointsDataSciencePrivateEndpoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String createdBy;
        private String dataScienceResourceType;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private String fqdn;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<String> nsgIds;
        private String state;
        private String subDomain;
        private String subnetId;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetPrivateEndpointsDataSciencePrivateEndpoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.dataScienceResourceType = defaults.dataScienceResourceType;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.fqdn = defaults.fqdn;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.nsgIds = defaults.nsgIds;
    	      this.state = defaults.state;
    	      this.subDomain = defaults.subDomain;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            this.createdBy = Objects.requireNonNull(createdBy);
            return this;
        }
        @CustomType.Setter
        public Builder dataScienceResourceType(String dataScienceResourceType) {
            this.dataScienceResourceType = Objects.requireNonNull(dataScienceResourceType);
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
        public Builder fqdn(String fqdn) {
            this.fqdn = Objects.requireNonNull(fqdn);
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
        public Builder nsgIds(List<String> nsgIds) {
            this.nsgIds = Objects.requireNonNull(nsgIds);
            return this;
        }
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder subDomain(String subDomain) {
            this.subDomain = Objects.requireNonNull(subDomain);
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
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
        public GetPrivateEndpointsDataSciencePrivateEndpoint build() {
            final var o = new GetPrivateEndpointsDataSciencePrivateEndpoint();
            o.compartmentId = compartmentId;
            o.createdBy = createdBy;
            o.dataScienceResourceType = dataScienceResourceType;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.fqdn = fqdn;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.nsgIds = nsgIds;
            o.state = state;
            o.subDomain = subDomain;
            o.subnetId = subnetId;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}