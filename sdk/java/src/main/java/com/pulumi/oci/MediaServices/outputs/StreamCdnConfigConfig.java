// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class StreamCdnConfigConfig {
    /**
     * @return (Updatable) The hostname of the CDN edge server to use when building CDN URLs.
     * 
     */
    private @Nullable String edgeHostname;
    /**
     * @return (Updatable) The path to prepend when building CDN URLs.
     * 
     */
    private @Nullable String edgePathPrefix;
    /**
     * @return (Updatable) The encryption key to use for edge token authentication.
     * 
     */
    private @Nullable String edgeTokenKey;
    /**
     * @return (Updatable) Salt to use when encrypting authentication token.
     * 
     */
    private @Nullable String edgeTokenSalt;
    /**
     * @return (Updatable) Whether token authentication should be used at the CDN edge.
     * 
     */
    private @Nullable Boolean isEdgeTokenAuth;
    /**
     * @return (Updatable) The shared secret key A, two for errorless key rotation.
     * 
     */
    private @Nullable String originAuthSecretKeyA;
    /**
     * @return (Updatable) The shared secret key B, two for errorless key rotation.
     * 
     */
    private @Nullable String originAuthSecretKeyB;
    /**
     * @return (Updatable) Nonce identifier for originAuthSecretKeyA (used to determine key used to sign).
     * 
     */
    private @Nullable String originAuthSecretKeyNonceA;
    /**
     * @return (Updatable) Nonce identifier for originAuthSecretKeyB (used to determine key used to sign).
     * 
     */
    private @Nullable String originAuthSecretKeyNonceB;
    /**
     * @return (Updatable) The type of encryption used to compute the signature.
     * 
     */
    private @Nullable String originAuthSignEncryption;
    /**
     * @return (Updatable) The type of data used to compute the signature.
     * 
     */
    private @Nullable String originAuthSignType;
    /**
     * @return (Updatable) The name of the CDN configuration type.
     * 
     */
    private String type;

    private StreamCdnConfigConfig() {}
    /**
     * @return (Updatable) The hostname of the CDN edge server to use when building CDN URLs.
     * 
     */
    public Optional<String> edgeHostname() {
        return Optional.ofNullable(this.edgeHostname);
    }
    /**
     * @return (Updatable) The path to prepend when building CDN URLs.
     * 
     */
    public Optional<String> edgePathPrefix() {
        return Optional.ofNullable(this.edgePathPrefix);
    }
    /**
     * @return (Updatable) The encryption key to use for edge token authentication.
     * 
     */
    public Optional<String> edgeTokenKey() {
        return Optional.ofNullable(this.edgeTokenKey);
    }
    /**
     * @return (Updatable) Salt to use when encrypting authentication token.
     * 
     */
    public Optional<String> edgeTokenSalt() {
        return Optional.ofNullable(this.edgeTokenSalt);
    }
    /**
     * @return (Updatable) Whether token authentication should be used at the CDN edge.
     * 
     */
    public Optional<Boolean> isEdgeTokenAuth() {
        return Optional.ofNullable(this.isEdgeTokenAuth);
    }
    /**
     * @return (Updatable) The shared secret key A, two for errorless key rotation.
     * 
     */
    public Optional<String> originAuthSecretKeyA() {
        return Optional.ofNullable(this.originAuthSecretKeyA);
    }
    /**
     * @return (Updatable) The shared secret key B, two for errorless key rotation.
     * 
     */
    public Optional<String> originAuthSecretKeyB() {
        return Optional.ofNullable(this.originAuthSecretKeyB);
    }
    /**
     * @return (Updatable) Nonce identifier for originAuthSecretKeyA (used to determine key used to sign).
     * 
     */
    public Optional<String> originAuthSecretKeyNonceA() {
        return Optional.ofNullable(this.originAuthSecretKeyNonceA);
    }
    /**
     * @return (Updatable) Nonce identifier for originAuthSecretKeyB (used to determine key used to sign).
     * 
     */
    public Optional<String> originAuthSecretKeyNonceB() {
        return Optional.ofNullable(this.originAuthSecretKeyNonceB);
    }
    /**
     * @return (Updatable) The type of encryption used to compute the signature.
     * 
     */
    public Optional<String> originAuthSignEncryption() {
        return Optional.ofNullable(this.originAuthSignEncryption);
    }
    /**
     * @return (Updatable) The type of data used to compute the signature.
     * 
     */
    public Optional<String> originAuthSignType() {
        return Optional.ofNullable(this.originAuthSignType);
    }
    /**
     * @return (Updatable) The name of the CDN configuration type.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(StreamCdnConfigConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String edgeHostname;
        private @Nullable String edgePathPrefix;
        private @Nullable String edgeTokenKey;
        private @Nullable String edgeTokenSalt;
        private @Nullable Boolean isEdgeTokenAuth;
        private @Nullable String originAuthSecretKeyA;
        private @Nullable String originAuthSecretKeyB;
        private @Nullable String originAuthSecretKeyNonceA;
        private @Nullable String originAuthSecretKeyNonceB;
        private @Nullable String originAuthSignEncryption;
        private @Nullable String originAuthSignType;
        private String type;
        public Builder() {}
        public Builder(StreamCdnConfigConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.edgeHostname = defaults.edgeHostname;
    	      this.edgePathPrefix = defaults.edgePathPrefix;
    	      this.edgeTokenKey = defaults.edgeTokenKey;
    	      this.edgeTokenSalt = defaults.edgeTokenSalt;
    	      this.isEdgeTokenAuth = defaults.isEdgeTokenAuth;
    	      this.originAuthSecretKeyA = defaults.originAuthSecretKeyA;
    	      this.originAuthSecretKeyB = defaults.originAuthSecretKeyB;
    	      this.originAuthSecretKeyNonceA = defaults.originAuthSecretKeyNonceA;
    	      this.originAuthSecretKeyNonceB = defaults.originAuthSecretKeyNonceB;
    	      this.originAuthSignEncryption = defaults.originAuthSignEncryption;
    	      this.originAuthSignType = defaults.originAuthSignType;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder edgeHostname(@Nullable String edgeHostname) {
            this.edgeHostname = edgeHostname;
            return this;
        }
        @CustomType.Setter
        public Builder edgePathPrefix(@Nullable String edgePathPrefix) {
            this.edgePathPrefix = edgePathPrefix;
            return this;
        }
        @CustomType.Setter
        public Builder edgeTokenKey(@Nullable String edgeTokenKey) {
            this.edgeTokenKey = edgeTokenKey;
            return this;
        }
        @CustomType.Setter
        public Builder edgeTokenSalt(@Nullable String edgeTokenSalt) {
            this.edgeTokenSalt = edgeTokenSalt;
            return this;
        }
        @CustomType.Setter
        public Builder isEdgeTokenAuth(@Nullable Boolean isEdgeTokenAuth) {
            this.isEdgeTokenAuth = isEdgeTokenAuth;
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyA(@Nullable String originAuthSecretKeyA) {
            this.originAuthSecretKeyA = originAuthSecretKeyA;
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyB(@Nullable String originAuthSecretKeyB) {
            this.originAuthSecretKeyB = originAuthSecretKeyB;
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyNonceA(@Nullable String originAuthSecretKeyNonceA) {
            this.originAuthSecretKeyNonceA = originAuthSecretKeyNonceA;
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyNonceB(@Nullable String originAuthSecretKeyNonceB) {
            this.originAuthSecretKeyNonceB = originAuthSecretKeyNonceB;
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSignEncryption(@Nullable String originAuthSignEncryption) {
            this.originAuthSignEncryption = originAuthSignEncryption;
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSignType(@Nullable String originAuthSignType) {
            this.originAuthSignType = originAuthSignType;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public StreamCdnConfigConfig build() {
            final var o = new StreamCdnConfigConfig();
            o.edgeHostname = edgeHostname;
            o.edgePathPrefix = edgePathPrefix;
            o.edgeTokenKey = edgeTokenKey;
            o.edgeTokenSalt = edgeTokenSalt;
            o.isEdgeTokenAuth = isEdgeTokenAuth;
            o.originAuthSecretKeyA = originAuthSecretKeyA;
            o.originAuthSecretKeyB = originAuthSecretKeyB;
            o.originAuthSecretKeyNonceA = originAuthSecretKeyNonceA;
            o.originAuthSecretKeyNonceB = originAuthSecretKeyNonceB;
            o.originAuthSignEncryption = originAuthSignEncryption;
            o.originAuthSignType = originAuthSignType;
            o.type = type;
            return o;
        }
    }
}