// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetKeyVersionArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetKeyVersionArgs Empty = new GetKeyVersionArgs();

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
     * The OCID of the key version.
     * 
     */
    @Import(name="keyVersionId", required=true)
    private Output<String> keyVersionId;

    /**
     * @return The OCID of the key version.
     * 
     */
    public Output<String> keyVersionId() {
        return this.keyVersionId;
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

    private GetKeyVersionArgs() {}

    private GetKeyVersionArgs(GetKeyVersionArgs $) {
        this.keyId = $.keyId;
        this.keyVersionId = $.keyVersionId;
        this.managementEndpoint = $.managementEndpoint;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetKeyVersionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetKeyVersionArgs $;

        public Builder() {
            $ = new GetKeyVersionArgs();
        }

        public Builder(GetKeyVersionArgs defaults) {
            $ = new GetKeyVersionArgs(Objects.requireNonNull(defaults));
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
         * @param keyVersionId The OCID of the key version.
         * 
         * @return builder
         * 
         */
        public Builder keyVersionId(Output<String> keyVersionId) {
            $.keyVersionId = keyVersionId;
            return this;
        }

        /**
         * @param keyVersionId The OCID of the key version.
         * 
         * @return builder
         * 
         */
        public Builder keyVersionId(String keyVersionId) {
            return keyVersionId(Output.of(keyVersionId));
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

        public GetKeyVersionArgs build() {
            $.keyId = Objects.requireNonNull($.keyId, "expected parameter 'keyId' to be non-null");
            $.keyVersionId = Objects.requireNonNull($.keyVersionId, "expected parameter 'keyVersionId' to be non-null");
            $.managementEndpoint = Objects.requireNonNull($.managementEndpoint, "expected parameter 'managementEndpoint' to be non-null");
            return $;
        }
    }

}