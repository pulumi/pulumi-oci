// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetSecurityListsSecurityListEgressSecurityRule;
import com.pulumi.oci.Core.outputs.GetSecurityListsSecurityListIngressSecurityRule;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSecurityListsSecurityList {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return Rules for allowing egress IP packets.
     * 
     */
    private List<GetSecurityListsSecurityListEgressSecurityRule> egressSecurityRules;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The security list&#39;s Oracle Cloud ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     * 
     */
    private String id;
    /**
     * @return Rules for allowing ingress IP packets.
     * 
     */
    private List<GetSecurityListsSecurityListIngressSecurityRule> ingressSecurityRules;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return The date and time the security list was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    private String vcnId;

    private GetSecurityListsSecurityList() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Rules for allowing egress IP packets.
     * 
     */
    public List<GetSecurityListsSecurityListEgressSecurityRule> egressSecurityRules() {
        return this.egressSecurityRules;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The security list&#39;s Oracle Cloud ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Rules for allowing ingress IP packets.
     * 
     */
    public List<GetSecurityListsSecurityListIngressSecurityRule> ingressSecurityRules() {
        return this.ingressSecurityRules;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the security list was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityListsSecurityList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private List<GetSecurityListsSecurityListEgressSecurityRule> egressSecurityRules;
        private Map<String,String> freeformTags;
        private String id;
        private List<GetSecurityListsSecurityListIngressSecurityRule> ingressSecurityRules;
        private String state;
        private String timeCreated;
        private String vcnId;
        public Builder() {}
        public Builder(GetSecurityListsSecurityList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.egressSecurityRules = defaults.egressSecurityRules;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.ingressSecurityRules = defaults.ingressSecurityRules;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder egressSecurityRules(List<GetSecurityListsSecurityListEgressSecurityRule> egressSecurityRules) {
            if (egressSecurityRules == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "egressSecurityRules");
            }
            this.egressSecurityRules = egressSecurityRules;
            return this;
        }
        public Builder egressSecurityRules(GetSecurityListsSecurityListEgressSecurityRule... egressSecurityRules) {
            return egressSecurityRules(List.of(egressSecurityRules));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ingressSecurityRules(List<GetSecurityListsSecurityListIngressSecurityRule> ingressSecurityRules) {
            if (ingressSecurityRules == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "ingressSecurityRules");
            }
            this.ingressSecurityRules = ingressSecurityRules;
            return this;
        }
        public Builder ingressSecurityRules(GetSecurityListsSecurityListIngressSecurityRule... ingressSecurityRules) {
            return ingressSecurityRules(List.of(ingressSecurityRules));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            if (vcnId == null) {
              throw new MissingRequiredPropertyException("GetSecurityListsSecurityList", "vcnId");
            }
            this.vcnId = vcnId;
            return this;
        }
        public GetSecurityListsSecurityList build() {
            final var _resultValue = new GetSecurityListsSecurityList();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.egressSecurityRules = egressSecurityRules;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.ingressSecurityRules = ingressSecurityRules;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.vcnId = vcnId;
            return _resultValue;
        }
    }
}
