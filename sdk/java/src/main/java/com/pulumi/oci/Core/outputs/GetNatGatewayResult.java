// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetNatGatewayResult {
    /**
     * @return Whether the NAT gateway blocks traffic through it. The default is `false`.  Example: `true`
     * 
     */
    private final Boolean blockTraffic;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the NAT gateway.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the NAT gateway.
     * 
     */
    private final String id;
    private final String natGatewayId;
    /**
     * @return The IP address associated with the NAT gateway.
     * 
     */
    private final String natIp;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the public IP address associated with the NAT gateway.
     * 
     */
    private final String publicIpId;
    /**
     * @return The NAT gateway&#39;s current state.
     * 
     */
    private final String state;
    /**
     * @return The date and time the NAT gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the NAT gateway belongs to.
     * 
     */
    private final String vcnId;

    @CustomType.Constructor
    private GetNatGatewayResult(
        @CustomType.Parameter("blockTraffic") Boolean blockTraffic,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("natGatewayId") String natGatewayId,
        @CustomType.Parameter("natIp") String natIp,
        @CustomType.Parameter("publicIpId") String publicIpId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("vcnId") String vcnId) {
        this.blockTraffic = blockTraffic;
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.natGatewayId = natGatewayId;
        this.natIp = natIp;
        this.publicIpId = publicIpId;
        this.state = state;
        this.timeCreated = timeCreated;
        this.vcnId = vcnId;
    }

    /**
     * @return Whether the NAT gateway blocks traffic through it. The default is `false`.  Example: `true`
     * 
     */
    public Boolean blockTraffic() {
        return this.blockTraffic;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the NAT gateway.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
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
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the NAT gateway.
     * 
     */
    public String id() {
        return this.id;
    }
    public String natGatewayId() {
        return this.natGatewayId;
    }
    /**
     * @return The IP address associated with the NAT gateway.
     * 
     */
    public String natIp() {
        return this.natIp;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the public IP address associated with the NAT gateway.
     * 
     */
    public String publicIpId() {
        return this.publicIpId;
    }
    /**
     * @return The NAT gateway&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the NAT gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the NAT gateway belongs to.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNatGatewayResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean blockTraffic;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String natGatewayId;
        private String natIp;
        private String publicIpId;
        private String state;
        private String timeCreated;
        private String vcnId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetNatGatewayResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockTraffic = defaults.blockTraffic;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.natGatewayId = defaults.natGatewayId;
    	      this.natIp = defaults.natIp;
    	      this.publicIpId = defaults.publicIpId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vcnId = defaults.vcnId;
        }

        public Builder blockTraffic(Boolean blockTraffic) {
            this.blockTraffic = Objects.requireNonNull(blockTraffic);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder natGatewayId(String natGatewayId) {
            this.natGatewayId = Objects.requireNonNull(natGatewayId);
            return this;
        }
        public Builder natIp(String natIp) {
            this.natIp = Objects.requireNonNull(natIp);
            return this;
        }
        public Builder publicIpId(String publicIpId) {
            this.publicIpId = Objects.requireNonNull(publicIpId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder vcnId(String vcnId) {
            this.vcnId = Objects.requireNonNull(vcnId);
            return this;
        }        public GetNatGatewayResult build() {
            return new GetNatGatewayResult(blockTraffic, compartmentId, definedTags, displayName, freeformTags, id, natGatewayId, natIp, publicIpId, state, timeCreated, vcnId);
        }
    }
}
