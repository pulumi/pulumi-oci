// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCnvDnsResolverAssociationResult {
    /**
     * @return The OCID of the DNS resolver in the association. We won&#39;t have the DNS resolver id as soon as vcn
     * is created, we will create it asynchronously. It would be null until it is actually created.
     * 
     */
    private String dnsResolverId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String state;
    /**
     * @return The OCID of the VCN in the association.
     * 
     */
    private String vcnId;

    private GetCnvDnsResolverAssociationResult() {}
    /**
     * @return The OCID of the DNS resolver in the association. We won&#39;t have the DNS resolver id as soon as vcn
     * is created, we will create it asynchronously. It would be null until it is actually created.
     * 
     */
    public String dnsResolverId() {
        return this.dnsResolverId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String state() {
        return this.state;
    }
    /**
     * @return The OCID of the VCN in the association.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCnvDnsResolverAssociationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dnsResolverId;
        private String id;
        private String state;
        private String vcnId;
        public Builder() {}
        public Builder(GetCnvDnsResolverAssociationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dnsResolverId = defaults.dnsResolverId;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder dnsResolverId(String dnsResolverId) {
            if (dnsResolverId == null) {
              throw new MissingRequiredPropertyException("GetCnvDnsResolverAssociationResult", "dnsResolverId");
            }
            this.dnsResolverId = dnsResolverId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCnvDnsResolverAssociationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetCnvDnsResolverAssociationResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            if (vcnId == null) {
              throw new MissingRequiredPropertyException("GetCnvDnsResolverAssociationResult", "vcnId");
            }
            this.vcnId = vcnId;
            return this;
        }
        public GetCnvDnsResolverAssociationResult build() {
            final var _resultValue = new GetCnvDnsResolverAssociationResult();
            _resultValue.dnsResolverId = dnsResolverId;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.vcnId = vcnId;
            return _resultValue;
        }
    }
}
