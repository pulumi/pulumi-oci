// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItem {
    /**
     * @return The value of the ICMP6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    private Integer icmpCode;
    /**
     * @return The value of the ICMP6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    private Integer icmpType;
    /**
     * @return Name of the application.
     * 
     */
    private String name;
    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    private String networkFirewallPolicyId;
    /**
     * @return OCID of the Network Firewall Policy this application belongs to.
     * 
     */
    private String parentResourceId;
    /**
     * @return Describes the type of Application.
     * 
     */
    private String type;

    private GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItem() {}
    /**
     * @return The value of the ICMP6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    public Integer icmpCode() {
        return this.icmpCode;
    }
    /**
     * @return The value of the ICMP6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    public Integer icmpType() {
        return this.icmpType;
    }
    /**
     * @return Name of the application.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public String networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * @return OCID of the Network Firewall Policy this application belongs to.
     * 
     */
    public String parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * @return Describes the type of Application.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer icmpCode;
        private Integer icmpType;
        private String name;
        private String networkFirewallPolicyId;
        private String parentResourceId;
        private String type;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.icmpCode = defaults.icmpCode;
    	      this.icmpType = defaults.icmpType;
    	      this.name = defaults.name;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
    	      this.parentResourceId = defaults.parentResourceId;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder icmpCode(Integer icmpCode) {
            this.icmpCode = Objects.requireNonNull(icmpCode);
            return this;
        }
        @CustomType.Setter
        public Builder icmpType(Integer icmpType) {
            this.icmpType = Objects.requireNonNull(icmpType);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            this.networkFirewallPolicyId = Objects.requireNonNull(networkFirewallPolicyId);
            return this;
        }
        @CustomType.Setter
        public Builder parentResourceId(String parentResourceId) {
            this.parentResourceId = Objects.requireNonNull(parentResourceId);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItem build() {
            final var o = new GetNetworkFirewallPolicyApplicationsApplicationSummaryCollectionItem();
            o.icmpCode = icmpCode;
            o.icmpType = icmpType;
            o.name = name;
            o.networkFirewallPolicyId = networkFirewallPolicyId;
            o.parentResourceId = parentResourceId;
            o.type = type;
            return o;
        }
    }
}