// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPublicIpResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the entity the public IP is assigned to, or in the process of being assigned to.
     * 
     */
    private String assignedEntityId;
    /**
     * @return The type of entity the public IP is assigned to, or in the process of being assigned to.
     * 
     */
    private String assignedEntityType;
    /**
     * @return The public IP&#39;s availability domain. This property is set only for ephemeral public IPs that are assigned to a private IP (that is, when the `scope` of the public IP is set to AVAILABILITY_DOMAIN). The value is the availability domain of the assigned private IP.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP. For an ephemeral public IP, this is the compartment of its assigned entity (which can be a private IP or a regional entity such as a NAT gateway). For a reserved public IP that is currently assigned, its compartment can be different from the assigned private IP&#39;s.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The public IP&#39;s Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     * 
     */
    private String id;
    /**
     * @return The public IP address of the `publicIp` object.  Example: `203.0.113.2`
     * 
     */
    private String ipAddress;
    /**
     * @return Defines when the public IP is deleted and released back to Oracle&#39;s public IP pool.
     * * `EPHEMERAL`: The lifetime is tied to the lifetime of its assigned entity. An ephemeral public IP must always be assigned to an entity. If the assigned entity is a private IP, the ephemeral public IP is automatically deleted when the private IP is deleted, when the VNIC is terminated, or when the instance is terminated. If the assigned entity is a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/), the ephemeral public IP is automatically deleted when the NAT gateway is terminated.
     * * `RESERVED`: You control the public IP&#39;s lifetime. You can delete a reserved public IP whenever you like. It does not need to be assigned to a private IP at all times.
     * 
     */
    private String lifetime;
    /**
     * @return Deprecated. Use `assignedEntityId` instead.
     * 
     */
    private String privateIpId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pool object created in the current tenancy.
     * 
     */
    private String publicIpPoolId;
    /**
     * @return Whether the public IP is regional or specific to a particular availability domain.
     * * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs and ephemeral public IPs assigned to a regional entity have `scope` = `REGION`.
     * * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it&#39;s assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
     * 
     */
    private String scope;
    /**
     * @return The public IP&#39;s current state.
     * 
     */
    private String state;
    /**
     * @return The date and time the public IP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetPublicIpResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the entity the public IP is assigned to, or in the process of being assigned to.
     * 
     */
    public String assignedEntityId() {
        return this.assignedEntityId;
    }
    /**
     * @return The type of entity the public IP is assigned to, or in the process of being assigned to.
     * 
     */
    public String assignedEntityType() {
        return this.assignedEntityType;
    }
    /**
     * @return The public IP&#39;s availability domain. This property is set only for ephemeral public IPs that are assigned to a private IP (that is, when the `scope` of the public IP is set to AVAILABILITY_DOMAIN). The value is the availability domain of the assigned private IP.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP. For an ephemeral public IP, this is the compartment of its assigned entity (which can be a private IP or a regional entity such as a NAT gateway). For a reserved public IP that is currently assigned, its compartment can be different from the assigned private IP&#39;s.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The public IP&#39;s Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The public IP address of the `publicIp` object.  Example: `203.0.113.2`
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return Defines when the public IP is deleted and released back to Oracle&#39;s public IP pool.
     * * `EPHEMERAL`: The lifetime is tied to the lifetime of its assigned entity. An ephemeral public IP must always be assigned to an entity. If the assigned entity is a private IP, the ephemeral public IP is automatically deleted when the private IP is deleted, when the VNIC is terminated, or when the instance is terminated. If the assigned entity is a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/), the ephemeral public IP is automatically deleted when the NAT gateway is terminated.
     * * `RESERVED`: You control the public IP&#39;s lifetime. You can delete a reserved public IP whenever you like. It does not need to be assigned to a private IP at all times.
     * 
     */
    public String lifetime() {
        return this.lifetime;
    }
    /**
     * @return Deprecated. Use `assignedEntityId` instead.
     * 
     */
    public String privateIpId() {
        return this.privateIpId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pool object created in the current tenancy.
     * 
     */
    public String publicIpPoolId() {
        return this.publicIpPoolId;
    }
    /**
     * @return Whether the public IP is regional or specific to a particular availability domain.
     * * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs and ephemeral public IPs assigned to a regional entity have `scope` = `REGION`.
     * * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it&#39;s assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
     * 
     */
    public String scope() {
        return this.scope;
    }
    /**
     * @return The public IP&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the public IP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPublicIpResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String assignedEntityId;
        private String assignedEntityType;
        private String availabilityDomain;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String ipAddress;
        private String lifetime;
        private String privateIpId;
        private String publicIpPoolId;
        private String scope;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetPublicIpResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.assignedEntityId = defaults.assignedEntityId;
    	      this.assignedEntityType = defaults.assignedEntityType;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.ipAddress = defaults.ipAddress;
    	      this.lifetime = defaults.lifetime;
    	      this.privateIpId = defaults.privateIpId;
    	      this.publicIpPoolId = defaults.publicIpPoolId;
    	      this.scope = defaults.scope;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder assignedEntityId(String assignedEntityId) {
            if (assignedEntityId == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "assignedEntityId");
            }
            this.assignedEntityId = assignedEntityId;
            return this;
        }
        @CustomType.Setter
        public Builder assignedEntityType(String assignedEntityType) {
            if (assignedEntityType == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "assignedEntityType");
            }
            this.assignedEntityType = assignedEntityType;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder lifetime(String lifetime) {
            if (lifetime == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "lifetime");
            }
            this.lifetime = lifetime;
            return this;
        }
        @CustomType.Setter
        public Builder privateIpId(String privateIpId) {
            if (privateIpId == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "privateIpId");
            }
            this.privateIpId = privateIpId;
            return this;
        }
        @CustomType.Setter
        public Builder publicIpPoolId(String publicIpPoolId) {
            if (publicIpPoolId == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "publicIpPoolId");
            }
            this.publicIpPoolId = publicIpPoolId;
            return this;
        }
        @CustomType.Setter
        public Builder scope(String scope) {
            if (scope == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "scope");
            }
            this.scope = scope;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetPublicIpResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetPublicIpResult build() {
            final var _resultValue = new GetPublicIpResult();
            _resultValue.assignedEntityId = assignedEntityId;
            _resultValue.assignedEntityType = assignedEntityType;
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.ipAddress = ipAddress;
            _resultValue.lifetime = lifetime;
            _resultValue.privateIpId = privateIpId;
            _resultValue.publicIpPoolId = publicIpPoolId;
            _resultValue.scope = scope;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
