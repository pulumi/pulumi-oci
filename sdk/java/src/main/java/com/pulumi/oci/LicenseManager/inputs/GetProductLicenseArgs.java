// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LicenseManager.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetProductLicenseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProductLicenseArgs Empty = new GetProductLicenseArgs();

    /**
     * Unique product license identifier.
     * 
     */
    @Import(name="productLicenseId", required=true)
    private Output<String> productLicenseId;

    /**
     * @return Unique product license identifier.
     * 
     */
    public Output<String> productLicenseId() {
        return this.productLicenseId;
    }

    private GetProductLicenseArgs() {}

    private GetProductLicenseArgs(GetProductLicenseArgs $) {
        this.productLicenseId = $.productLicenseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProductLicenseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProductLicenseArgs $;

        public Builder() {
            $ = new GetProductLicenseArgs();
        }

        public Builder(GetProductLicenseArgs defaults) {
            $ = new GetProductLicenseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param productLicenseId Unique product license identifier.
         * 
         * @return builder
         * 
         */
        public Builder productLicenseId(Output<String> productLicenseId) {
            $.productLicenseId = productLicenseId;
            return this;
        }

        /**
         * @param productLicenseId Unique product license identifier.
         * 
         * @return builder
         * 
         */
        public Builder productLicenseId(String productLicenseId) {
            return productLicenseId(Output.of(productLicenseId));
        }

        public GetProductLicenseArgs build() {
            if ($.productLicenseId == null) {
                throw new MissingRequiredPropertyException("GetProductLicenseArgs", "productLicenseId");
            }
            return $;
        }
    }

}
