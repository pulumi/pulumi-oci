// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetKeyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetKeyArgs Empty = new GetKeyArgs();

    /**
     * The OCID of the key.
     * 
     */
    @Import(name="keyId", required=true)
    private Output<String> keyId;

    /**
     * @return The OCID of the key.
     * 
     */
    public Output<String> keyId() {
        return this.keyId;
    }

    /**
     * The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
     * 
     */
    @Import(name="managementEndpoint", required=true)
    private Output<String> managementEndpoint;

    /**
     * @return The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
     * 
     */
    public Output<String> managementEndpoint() {
        return this.managementEndpoint;
    }

    private GetKeyArgs() {}

    private GetKeyArgs(GetKeyArgs $) {
        this.keyId = $.keyId;
        this.managementEndpoint = $.managementEndpoint;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetKeyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetKeyArgs $;

        public Builder() {
            $ = new GetKeyArgs();
        }

        public Builder(GetKeyArgs defaults) {
            $ = new GetKeyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param keyId The OCID of the key.
         * 
         * @return builder
         * 
         */
        public Builder keyId(Output<String> keyId) {
            $.keyId = keyId;
            return this;
        }

        /**
         * @param keyId The OCID of the key.
         * 
         * @return builder
         * 
         */
        public Builder keyId(String keyId) {
            return keyId(Output.of(keyId));
        }

        /**
         * @param managementEndpoint The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
         * 
         * @return builder
         * 
         */
        public Builder managementEndpoint(Output<String> managementEndpoint) {
            $.managementEndpoint = managementEndpoint;
            return this;
        }

        /**
         * @param managementEndpoint The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
         * 
         * @return builder
         * 
         */
        public Builder managementEndpoint(String managementEndpoint) {
            return managementEndpoint(Output.of(managementEndpoint));
        }

        public GetKeyArgs build() {
            if ($.keyId == null) {
                throw new MissingRequiredPropertyException("GetKeyArgs", "keyId");
            }
            if ($.managementEndpoint == null) {
                throw new MissingRequiredPropertyException("GetKeyArgs", "managementEndpoint");
            }
            return $;
        }
    }

}
