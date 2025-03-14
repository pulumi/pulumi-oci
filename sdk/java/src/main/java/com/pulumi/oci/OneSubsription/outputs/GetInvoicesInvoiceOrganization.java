// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInvoicesInvoiceOrganization {
    /**
     * @return Payment Term name
     * 
     */
    private String name;
    /**
     * @return Organization ID
     * 
     */
    private Double number;

    private GetInvoicesInvoiceOrganization() {}
    /**
     * @return Payment Term name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Organization ID
     * 
     */
    public Double number() {
        return this.number;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvoicesInvoiceOrganization defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private Double number;
        public Builder() {}
        public Builder(GetInvoicesInvoiceOrganization defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.number = defaults.number;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetInvoicesInvoiceOrganization", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder number(Double number) {
            if (number == null) {
              throw new MissingRequiredPropertyException("GetInvoicesInvoiceOrganization", "number");
            }
            this.number = number;
            return this;
        }
        public GetInvoicesInvoiceOrganization build() {
            final var _resultValue = new GetInvoicesInvoiceOrganization();
            _resultValue.name = name;
            _resultValue.number = number;
            return _resultValue;
        }
    }
}
