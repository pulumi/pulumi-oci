// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Kms.inputs.GetKeysFilterArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetKeysArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetKeysArgs Empty = new GetKeysArgs();

    /**
     * The algorithm used by a key&#39;s key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
     * 
     */
    @Import(name="algorithm")
    private @Nullable Output<String> algorithm;

    /**
     * @return The algorithm used by a key&#39;s key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
     * 
     */
    public Optional<Output<String>> algorithm() {
        return Optional.ofNullable(this.algorithm);
    }

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The curve ID of the keys. (This pertains only to ECDSA keys.)
     * 
     */
    @Import(name="curveId")
    private @Nullable Output<String> curveId;

    /**
     * @return The curve ID of the keys. (This pertains only to ECDSA keys.)
     * 
     */
    public Optional<Output<String>> curveId() {
        return Optional.ofNullable(this.curveId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetKeysFilterArgs>> filters;

    public Optional<Output<List<GetKeysFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
     * 
     */
    @Import(name="length")
    private @Nullable Output<Integer> length;

    /**
     * @return The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
     * 
     */
    public Optional<Output<Integer>> length() {
        return Optional.ofNullable(this.length);
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

    /**
     * A key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. A protection mode of `EXTERNAL` mean that the key persists on the customer&#39;s external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of `EXTERNAL` are performed by external key manager.
     * 
     */
    @Import(name="protectionMode")
    private @Nullable Output<String> protectionMode;

    /**
     * @return A key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. A protection mode of `EXTERNAL` mean that the key persists on the customer&#39;s external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of `EXTERNAL` are performed by external key manager.
     * 
     */
    public Optional<Output<String>> protectionMode() {
        return Optional.ofNullable(this.protectionMode);
    }

    private GetKeysArgs() {}

    private GetKeysArgs(GetKeysArgs $) {
        this.algorithm = $.algorithm;
        this.compartmentId = $.compartmentId;
        this.curveId = $.curveId;
        this.filters = $.filters;
        this.length = $.length;
        this.managementEndpoint = $.managementEndpoint;
        this.protectionMode = $.protectionMode;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetKeysArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetKeysArgs $;

        public Builder() {
            $ = new GetKeysArgs();
        }

        public Builder(GetKeysArgs defaults) {
            $ = new GetKeysArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param algorithm The algorithm used by a key&#39;s key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
         * 
         * @return builder
         * 
         */
        public Builder algorithm(@Nullable Output<String> algorithm) {
            $.algorithm = algorithm;
            return this;
        }

        /**
         * @param algorithm The algorithm used by a key&#39;s key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
         * 
         * @return builder
         * 
         */
        public Builder algorithm(String algorithm) {
            return algorithm(Output.of(algorithm));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param curveId The curve ID of the keys. (This pertains only to ECDSA keys.)
         * 
         * @return builder
         * 
         */
        public Builder curveId(@Nullable Output<String> curveId) {
            $.curveId = curveId;
            return this;
        }

        /**
         * @param curveId The curve ID of the keys. (This pertains only to ECDSA keys.)
         * 
         * @return builder
         * 
         */
        public Builder curveId(String curveId) {
            return curveId(Output.of(curveId));
        }

        public Builder filters(@Nullable Output<List<GetKeysFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetKeysFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetKeysFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param length The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
         * 
         * @return builder
         * 
         */
        public Builder length(@Nullable Output<Integer> length) {
            $.length = length;
            return this;
        }

        /**
         * @param length The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
         * 
         * @return builder
         * 
         */
        public Builder length(Integer length) {
            return length(Output.of(length));
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

        /**
         * @param protectionMode A key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. A protection mode of `EXTERNAL` mean that the key persists on the customer&#39;s external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of `EXTERNAL` are performed by external key manager.
         * 
         * @return builder
         * 
         */
        public Builder protectionMode(@Nullable Output<String> protectionMode) {
            $.protectionMode = protectionMode;
            return this;
        }

        /**
         * @param protectionMode A key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. A protection mode of `EXTERNAL` mean that the key persists on the customer&#39;s external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of `EXTERNAL` are performed by external key manager.
         * 
         * @return builder
         * 
         */
        public Builder protectionMode(String protectionMode) {
            return protectionMode(Output.of(protectionMode));
        }

        public GetKeysArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetKeysArgs", "compartmentId");
            }
            if ($.managementEndpoint == null) {
                throw new MissingRequiredPropertyException("GetKeysArgs", "managementEndpoint");
            }
            return $;
        }
    }

}
