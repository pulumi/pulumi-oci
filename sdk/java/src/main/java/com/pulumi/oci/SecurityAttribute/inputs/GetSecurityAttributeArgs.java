// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.SecurityAttribute.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSecurityAttributeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSecurityAttributeArgs Empty = new GetSecurityAttributeArgs();

    /**
     * The name of the security attribute.
     * 
     */
    @Import(name="securityAttributeName", required=true)
    private Output<String> securityAttributeName;

    /**
     * @return The name of the security attribute.
     * 
     */
    public Output<String> securityAttributeName() {
        return this.securityAttributeName;
    }

    /**
     * The OCID of the security attribute namespace.
     * 
     */
    @Import(name="securityAttributeNamespaceId", required=true)
    private Output<String> securityAttributeNamespaceId;

    /**
     * @return The OCID of the security attribute namespace.
     * 
     */
    public Output<String> securityAttributeNamespaceId() {
        return this.securityAttributeNamespaceId;
    }

    private GetSecurityAttributeArgs() {}

    private GetSecurityAttributeArgs(GetSecurityAttributeArgs $) {
        this.securityAttributeName = $.securityAttributeName;
        this.securityAttributeNamespaceId = $.securityAttributeNamespaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityAttributeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityAttributeArgs $;

        public Builder() {
            $ = new GetSecurityAttributeArgs();
        }

        public Builder(GetSecurityAttributeArgs defaults) {
            $ = new GetSecurityAttributeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param securityAttributeName The name of the security attribute.
         * 
         * @return builder
         * 
         */
        public Builder securityAttributeName(Output<String> securityAttributeName) {
            $.securityAttributeName = securityAttributeName;
            return this;
        }

        /**
         * @param securityAttributeName The name of the security attribute.
         * 
         * @return builder
         * 
         */
        public Builder securityAttributeName(String securityAttributeName) {
            return securityAttributeName(Output.of(securityAttributeName));
        }

        /**
         * @param securityAttributeNamespaceId The OCID of the security attribute namespace.
         * 
         * @return builder
         * 
         */
        public Builder securityAttributeNamespaceId(Output<String> securityAttributeNamespaceId) {
            $.securityAttributeNamespaceId = securityAttributeNamespaceId;
            return this;
        }

        /**
         * @param securityAttributeNamespaceId The OCID of the security attribute namespace.
         * 
         * @return builder
         * 
         */
        public Builder securityAttributeNamespaceId(String securityAttributeNamespaceId) {
            return securityAttributeNamespaceId(Output.of(securityAttributeNamespaceId));
        }

        public GetSecurityAttributeArgs build() {
            if ($.securityAttributeName == null) {
                throw new MissingRequiredPropertyException("GetSecurityAttributeArgs", "securityAttributeName");
            }
            if ($.securityAttributeNamespaceId == null) {
                throw new MissingRequiredPropertyException("GetSecurityAttributeArgs", "securityAttributeNamespaceId");
            }
            return $;
        }
    }

}
