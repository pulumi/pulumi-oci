// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetGatewayCaBundle;
import com.pulumi.oci.ApiGateway.outputs.GetGatewayIpAddress;
import com.pulumi.oci.ApiGateway.outputs.GetGatewayResponseCacheDetail;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetGatewayResult {
    /**
     * @return An array of CA bundles that should be used on the Gateway for TLS validation.
     * 
     */
    private List<GetGatewayCaBundle> caBundles;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private String certificateId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private String displayName;
    /**
     * @return Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
     * 
     */
    private String endpointType;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    private String gatewayId;
    /**
     * @return The hostname for APIs deployed on the gateway.
     * 
     */
    private String hostname;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private String id;
    /**
     * @return An array of IP addresses associated with the gateway.
     * 
     */
    private List<GetGatewayIpAddress> ipAddresses;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return An array of Network Security Groups OCIDs associated with this API Gateway.
     * 
     */
    private List<String> networkSecurityGroupIds;
    /**
     * @return Base Gateway response cache.
     * 
     */
    private List<GetGatewayResponseCacheDetail> responseCacheDetails;
    /**
     * @return The current state of the gateway.
     * 
     */
    private String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
     * 
     */
    private String subnetId;
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetGatewayResult() {}
    /**
     * @return An array of CA bundles that should be used on the Gateway for TLS validation.
     * 
     */
    public List<GetGatewayCaBundle> caBundles() {
        return this.caBundles;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public String certificateId() {
        return this.certificateId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
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
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
     * 
     */
    public String endpointType() {
        return this.endpointType;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    public String gatewayId() {
        return this.gatewayId;
    }
    /**
     * @return The hostname for APIs deployed on the gateway.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An array of IP addresses associated with the gateway.
     * 
     */
    public List<GetGatewayIpAddress> ipAddresses() {
        return this.ipAddresses;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return An array of Network Security Groups OCIDs associated with this API Gateway.
     * 
     */
    public List<String> networkSecurityGroupIds() {
        return this.networkSecurityGroupIds;
    }
    /**
     * @return Base Gateway response cache.
     * 
     */
    public List<GetGatewayResponseCacheDetail> responseCacheDetails() {
        return this.responseCacheDetails;
    }
    /**
     * @return The current state of the gateway.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGatewayResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetGatewayCaBundle> caBundles;
        private String certificateId;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private String endpointType;
        private Map<String,String> freeformTags;
        private String gatewayId;
        private String hostname;
        private String id;
        private List<GetGatewayIpAddress> ipAddresses;
        private String lifecycleDetails;
        private List<String> networkSecurityGroupIds;
        private List<GetGatewayResponseCacheDetail> responseCacheDetails;
        private String state;
        private String subnetId;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetGatewayResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.caBundles = defaults.caBundles;
    	      this.certificateId = defaults.certificateId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.endpointType = defaults.endpointType;
    	      this.freeformTags = defaults.freeformTags;
    	      this.gatewayId = defaults.gatewayId;
    	      this.hostname = defaults.hostname;
    	      this.id = defaults.id;
    	      this.ipAddresses = defaults.ipAddresses;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.networkSecurityGroupIds = defaults.networkSecurityGroupIds;
    	      this.responseCacheDetails = defaults.responseCacheDetails;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder caBundles(List<GetGatewayCaBundle> caBundles) {
            if (caBundles == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "caBundles");
            }
            this.caBundles = caBundles;
            return this;
        }
        public Builder caBundles(GetGatewayCaBundle... caBundles) {
            return caBundles(List.of(caBundles));
        }
        @CustomType.Setter
        public Builder certificateId(String certificateId) {
            if (certificateId == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "certificateId");
            }
            this.certificateId = certificateId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder endpointType(String endpointType) {
            if (endpointType == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "endpointType");
            }
            this.endpointType = endpointType;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder gatewayId(String gatewayId) {
            if (gatewayId == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "gatewayId");
            }
            this.gatewayId = gatewayId;
            return this;
        }
        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddresses(List<GetGatewayIpAddress> ipAddresses) {
            if (ipAddresses == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "ipAddresses");
            }
            this.ipAddresses = ipAddresses;
            return this;
        }
        public Builder ipAddresses(GetGatewayIpAddress... ipAddresses) {
            return ipAddresses(List.of(ipAddresses));
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder networkSecurityGroupIds(List<String> networkSecurityGroupIds) {
            if (networkSecurityGroupIds == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "networkSecurityGroupIds");
            }
            this.networkSecurityGroupIds = networkSecurityGroupIds;
            return this;
        }
        public Builder networkSecurityGroupIds(String... networkSecurityGroupIds) {
            return networkSecurityGroupIds(List.of(networkSecurityGroupIds));
        }
        @CustomType.Setter
        public Builder responseCacheDetails(List<GetGatewayResponseCacheDetail> responseCacheDetails) {
            if (responseCacheDetails == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "responseCacheDetails");
            }
            this.responseCacheDetails = responseCacheDetails;
            return this;
        }
        public Builder responseCacheDetails(GetGatewayResponseCacheDetail... responseCacheDetails) {
            return responseCacheDetails(List.of(responseCacheDetails));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            if (subnetId == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "subnetId");
            }
            this.subnetId = subnetId;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetGatewayResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetGatewayResult build() {
            final var _resultValue = new GetGatewayResult();
            _resultValue.caBundles = caBundles;
            _resultValue.certificateId = certificateId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.endpointType = endpointType;
            _resultValue.freeformTags = freeformTags;
            _resultValue.gatewayId = gatewayId;
            _resultValue.hostname = hostname;
            _resultValue.id = id;
            _resultValue.ipAddresses = ipAddresses;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.networkSecurityGroupIds = networkSecurityGroupIds;
            _resultValue.responseCacheDetails = responseCacheDetails;
            _resultValue.state = state;
            _resultValue.subnetId = subnetId;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
