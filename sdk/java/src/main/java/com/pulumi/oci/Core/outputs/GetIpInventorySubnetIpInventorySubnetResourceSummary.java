// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIpInventorySubnetIpInventorySubnetResourceSummary {
    /**
     * @return Address type of the allocated private IP address.
     * 
     */
    private String addressType;
    /**
     * @return Name of the created resource.
     * 
     */
    private String assignedResourceName;
    /**
     * @return Type of the resource.
     * 
     */
    private String assignedResourceType;
    /**
     * @return Assigned time of the private IP address.
     * 
     */
    private String assignedTime;
    /**
     * @return Associated public IP address for the private IP address.
     * 
     */
    private String associatedPublicIp;
    /**
     * @return Public IP address Pool the IP address is allocated from.
     * 
     */
    private String associatedPublicIpPool;
    /**
     * @return DNS hostname of the IP address.
     * 
     */
    private String dnsHostName;
    /**
     * @return Lists the allocated private IP address.
     * 
     */
    private String ipAddress;
    /**
     * @return Lifetime of the allocated private IP address.
     * 
     */
    private String ipAddressLifetime;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the IP address.
     * 
     */
    private String ipId;
    /**
     * @return The address range the IP address is assigned from.
     * 
     */
    private String parentCidr;
    /**
     * @return Lifetime of the assigned public IP address.
     * 
     */
    private String publicIpLifetime;

    private GetIpInventorySubnetIpInventorySubnetResourceSummary() {}
    /**
     * @return Address type of the allocated private IP address.
     * 
     */
    public String addressType() {
        return this.addressType;
    }
    /**
     * @return Name of the created resource.
     * 
     */
    public String assignedResourceName() {
        return this.assignedResourceName;
    }
    /**
     * @return Type of the resource.
     * 
     */
    public String assignedResourceType() {
        return this.assignedResourceType;
    }
    /**
     * @return Assigned time of the private IP address.
     * 
     */
    public String assignedTime() {
        return this.assignedTime;
    }
    /**
     * @return Associated public IP address for the private IP address.
     * 
     */
    public String associatedPublicIp() {
        return this.associatedPublicIp;
    }
    /**
     * @return Public IP address Pool the IP address is allocated from.
     * 
     */
    public String associatedPublicIpPool() {
        return this.associatedPublicIpPool;
    }
    /**
     * @return DNS hostname of the IP address.
     * 
     */
    public String dnsHostName() {
        return this.dnsHostName;
    }
    /**
     * @return Lists the allocated private IP address.
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return Lifetime of the allocated private IP address.
     * 
     */
    public String ipAddressLifetime() {
        return this.ipAddressLifetime;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the IP address.
     * 
     */
    public String ipId() {
        return this.ipId;
    }
    /**
     * @return The address range the IP address is assigned from.
     * 
     */
    public String parentCidr() {
        return this.parentCidr;
    }
    /**
     * @return Lifetime of the assigned public IP address.
     * 
     */
    public String publicIpLifetime() {
        return this.publicIpLifetime;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpInventorySubnetIpInventorySubnetResourceSummary defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String addressType;
        private String assignedResourceName;
        private String assignedResourceType;
        private String assignedTime;
        private String associatedPublicIp;
        private String associatedPublicIpPool;
        private String dnsHostName;
        private String ipAddress;
        private String ipAddressLifetime;
        private String ipId;
        private String parentCidr;
        private String publicIpLifetime;
        public Builder() {}
        public Builder(GetIpInventorySubnetIpInventorySubnetResourceSummary defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.addressType = defaults.addressType;
    	      this.assignedResourceName = defaults.assignedResourceName;
    	      this.assignedResourceType = defaults.assignedResourceType;
    	      this.assignedTime = defaults.assignedTime;
    	      this.associatedPublicIp = defaults.associatedPublicIp;
    	      this.associatedPublicIpPool = defaults.associatedPublicIpPool;
    	      this.dnsHostName = defaults.dnsHostName;
    	      this.ipAddress = defaults.ipAddress;
    	      this.ipAddressLifetime = defaults.ipAddressLifetime;
    	      this.ipId = defaults.ipId;
    	      this.parentCidr = defaults.parentCidr;
    	      this.publicIpLifetime = defaults.publicIpLifetime;
        }

        @CustomType.Setter
        public Builder addressType(String addressType) {
            if (addressType == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "addressType");
            }
            this.addressType = addressType;
            return this;
        }
        @CustomType.Setter
        public Builder assignedResourceName(String assignedResourceName) {
            if (assignedResourceName == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "assignedResourceName");
            }
            this.assignedResourceName = assignedResourceName;
            return this;
        }
        @CustomType.Setter
        public Builder assignedResourceType(String assignedResourceType) {
            if (assignedResourceType == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "assignedResourceType");
            }
            this.assignedResourceType = assignedResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder assignedTime(String assignedTime) {
            if (assignedTime == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "assignedTime");
            }
            this.assignedTime = assignedTime;
            return this;
        }
        @CustomType.Setter
        public Builder associatedPublicIp(String associatedPublicIp) {
            if (associatedPublicIp == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "associatedPublicIp");
            }
            this.associatedPublicIp = associatedPublicIp;
            return this;
        }
        @CustomType.Setter
        public Builder associatedPublicIpPool(String associatedPublicIpPool) {
            if (associatedPublicIpPool == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "associatedPublicIpPool");
            }
            this.associatedPublicIpPool = associatedPublicIpPool;
            return this;
        }
        @CustomType.Setter
        public Builder dnsHostName(String dnsHostName) {
            if (dnsHostName == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "dnsHostName");
            }
            this.dnsHostName = dnsHostName;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddressLifetime(String ipAddressLifetime) {
            if (ipAddressLifetime == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "ipAddressLifetime");
            }
            this.ipAddressLifetime = ipAddressLifetime;
            return this;
        }
        @CustomType.Setter
        public Builder ipId(String ipId) {
            if (ipId == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "ipId");
            }
            this.ipId = ipId;
            return this;
        }
        @CustomType.Setter
        public Builder parentCidr(String parentCidr) {
            if (parentCidr == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "parentCidr");
            }
            this.parentCidr = parentCidr;
            return this;
        }
        @CustomType.Setter
        public Builder publicIpLifetime(String publicIpLifetime) {
            if (publicIpLifetime == null) {
              throw new MissingRequiredPropertyException("GetIpInventorySubnetIpInventorySubnetResourceSummary", "publicIpLifetime");
            }
            this.publicIpLifetime = publicIpLifetime;
            return this;
        }
        public GetIpInventorySubnetIpInventorySubnetResourceSummary build() {
            final var _resultValue = new GetIpInventorySubnetIpInventorySubnetResourceSummary();
            _resultValue.addressType = addressType;
            _resultValue.assignedResourceName = assignedResourceName;
            _resultValue.assignedResourceType = assignedResourceType;
            _resultValue.assignedTime = assignedTime;
            _resultValue.associatedPublicIp = associatedPublicIp;
            _resultValue.associatedPublicIpPool = associatedPublicIpPool;
            _resultValue.dnsHostName = dnsHostName;
            _resultValue.ipAddress = ipAddress;
            _resultValue.ipAddressLifetime = ipAddressLifetime;
            _resultValue.ipId = ipId;
            _resultValue.parentCidr = parentCidr;
            _resultValue.publicIpLifetime = publicIpLifetime;
            return _resultValue;
        }
    }
}
