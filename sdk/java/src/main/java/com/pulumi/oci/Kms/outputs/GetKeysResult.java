// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Kms.outputs.GetKeysFilter;
import com.pulumi.oci.Kms.outputs.GetKeysKey;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetKeysResult {
    /**
     * @return The algorithm used by a key&#39;s key versions to encrypt or decrypt.
     * 
     */
    private final @Nullable String algorithm;
    /**
     * @return The OCID of the compartment that contains this master encryption key.
     * 
     */
    private final String compartmentId;
    /**
     * @return Supported curve IDs for ECDSA keys.
     * 
     */
    private final @Nullable String curveId;
    private final @Nullable List<GetKeysFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of keys.
     * 
     */
    private final List<GetKeysKey> keys;
    /**
     * @return The length of the key in bytes, expressed as an integer. Supported values include the following:
     * * AES: 16, 24, or 32
     * * RSA: 256, 384, or 512
     * * ECDSA: 32, 48, or 66
     * 
     */
    private final @Nullable Integer length;
    private final String managementEndpoint;
    /**
     * @return The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
     * 
     */
    private final @Nullable String protectionMode;

    @CustomType.Constructor
    private GetKeysResult(
        @CustomType.Parameter("algorithm") @Nullable String algorithm,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("curveId") @Nullable String curveId,
        @CustomType.Parameter("filters") @Nullable List<GetKeysFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("keys") List<GetKeysKey> keys,
        @CustomType.Parameter("length") @Nullable Integer length,
        @CustomType.Parameter("managementEndpoint") String managementEndpoint,
        @CustomType.Parameter("protectionMode") @Nullable String protectionMode) {
        this.algorithm = algorithm;
        this.compartmentId = compartmentId;
        this.curveId = curveId;
        this.filters = filters;
        this.id = id;
        this.keys = keys;
        this.length = length;
        this.managementEndpoint = managementEndpoint;
        this.protectionMode = protectionMode;
    }

    /**
     * @return The algorithm used by a key&#39;s key versions to encrypt or decrypt.
     * 
     */
    public Optional<String> algorithm() {
        return Optional.ofNullable(this.algorithm);
    }
    /**
     * @return The OCID of the compartment that contains this master encryption key.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Supported curve IDs for ECDSA keys.
     * 
     */
    public Optional<String> curveId() {
        return Optional.ofNullable(this.curveId);
    }
    public List<GetKeysFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of keys.
     * 
     */
    public List<GetKeysKey> keys() {
        return this.keys;
    }
    /**
     * @return The length of the key in bytes, expressed as an integer. Supported values include the following:
     * * AES: 16, 24, or 32
     * * RSA: 256, 384, or 512
     * * ECDSA: 32, 48, or 66
     * 
     */
    public Optional<Integer> length() {
        return Optional.ofNullable(this.length);
    }
    public String managementEndpoint() {
        return this.managementEndpoint;
    }
    /**
     * @return The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
     * 
     */
    public Optional<String> protectionMode() {
        return Optional.ofNullable(this.protectionMode);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeysResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String algorithm;
        private String compartmentId;
        private @Nullable String curveId;
        private @Nullable List<GetKeysFilter> filters;
        private String id;
        private List<GetKeysKey> keys;
        private @Nullable Integer length;
        private String managementEndpoint;
        private @Nullable String protectionMode;

        public Builder() {
    	      // Empty
        }

        public Builder(GetKeysResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.algorithm = defaults.algorithm;
    	      this.compartmentId = defaults.compartmentId;
    	      this.curveId = defaults.curveId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.keys = defaults.keys;
    	      this.length = defaults.length;
    	      this.managementEndpoint = defaults.managementEndpoint;
    	      this.protectionMode = defaults.protectionMode;
        }

        public Builder algorithm(@Nullable String algorithm) {
            this.algorithm = algorithm;
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder curveId(@Nullable String curveId) {
            this.curveId = curveId;
            return this;
        }
        public Builder filters(@Nullable List<GetKeysFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetKeysFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder keys(List<GetKeysKey> keys) {
            this.keys = Objects.requireNonNull(keys);
            return this;
        }
        public Builder keys(GetKeysKey... keys) {
            return keys(List.of(keys));
        }
        public Builder length(@Nullable Integer length) {
            this.length = length;
            return this;
        }
        public Builder managementEndpoint(String managementEndpoint) {
            this.managementEndpoint = Objects.requireNonNull(managementEndpoint);
            return this;
        }
        public Builder protectionMode(@Nullable String protectionMode) {
            this.protectionMode = protectionMode;
            return this;
        }        public GetKeysResult build() {
            return new GetKeysResult(algorithm, compartmentId, curveId, filters, id, keys, length, managementEndpoint, protectionMode);
        }
    }
}
