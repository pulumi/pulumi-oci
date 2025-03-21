// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetByoipRangeOriginAsn {
    /**
     * @return The as path prepend length.
     * 
     */
    private Integer asPathPrependLength;
    /**
     * @return The Autonomous System Number (ASN) you are importing to the Oracle cloud.
     * 
     */
    private String asn;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `Byoasn` resource.
     * 
     */
    private String byoasnId;

    private GetByoipRangeOriginAsn() {}
    /**
     * @return The as path prepend length.
     * 
     */
    public Integer asPathPrependLength() {
        return this.asPathPrependLength;
    }
    /**
     * @return The Autonomous System Number (ASN) you are importing to the Oracle cloud.
     * 
     */
    public String asn() {
        return this.asn;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `Byoasn` resource.
     * 
     */
    public String byoasnId() {
        return this.byoasnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetByoipRangeOriginAsn defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer asPathPrependLength;
        private String asn;
        private String byoasnId;
        public Builder() {}
        public Builder(GetByoipRangeOriginAsn defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.asPathPrependLength = defaults.asPathPrependLength;
    	      this.asn = defaults.asn;
    	      this.byoasnId = defaults.byoasnId;
        }

        @CustomType.Setter
        public Builder asPathPrependLength(Integer asPathPrependLength) {
            if (asPathPrependLength == null) {
              throw new MissingRequiredPropertyException("GetByoipRangeOriginAsn", "asPathPrependLength");
            }
            this.asPathPrependLength = asPathPrependLength;
            return this;
        }
        @CustomType.Setter
        public Builder asn(String asn) {
            if (asn == null) {
              throw new MissingRequiredPropertyException("GetByoipRangeOriginAsn", "asn");
            }
            this.asn = asn;
            return this;
        }
        @CustomType.Setter
        public Builder byoasnId(String byoasnId) {
            if (byoasnId == null) {
              throw new MissingRequiredPropertyException("GetByoipRangeOriginAsn", "byoasnId");
            }
            this.byoasnId = byoasnId;
            return this;
        }
        public GetByoipRangeOriginAsn build() {
            final var _resultValue = new GetByoipRangeOriginAsn();
            _resultValue.asPathPrependLength = asPathPrependLength;
            _resultValue.asn = asn;
            _resultValue.byoasnId = byoasnId;
            return _resultValue;
        }
    }
}
