// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetStreamCdnConfigConfig {
    /**
     * @return The hostname of the CDN edge server to use when building CDN URLs.
     * 
     */
    private String edgeHostname;
    /**
     * @return The path to prepend when building CDN URLs.
     * 
     */
    private String edgePathPrefix;
    /**
     * @return The encryption key to use for edge token authentication.
     * 
     */
    private String edgeTokenKey;
    /**
     * @return Salt to use when encrypting authentication token.
     * 
     */
    private String edgeTokenSalt;
    /**
     * @return Whether token authentication should be used at the CDN edge.
     * 
     */
    private Boolean isEdgeTokenAuth;
    /**
     * @return The shared secret key A, two for errorless key rotation.
     * 
     */
    private String originAuthSecretKeyA;
    /**
     * @return The shared secret key B, two for errorless key rotation.
     * 
     */
    private String originAuthSecretKeyB;
    /**
     * @return Nonce identifier for originAuthSecretKeyA (used to determine key used to sign).
     * 
     */
    private String originAuthSecretKeyNonceA;
    /**
     * @return Nonce identifier for originAuthSecretKeyB (used to determine key used to sign).
     * 
     */
    private String originAuthSecretKeyNonceB;
    /**
     * @return The type of encryption used to compute the signature.
     * 
     */
    private String originAuthSignEncryption;
    /**
     * @return The type of data used to compute the signature.
     * 
     */
    private String originAuthSignType;
    /**
     * @return The name of the CDN configuration type.
     * 
     */
    private String type;

    private GetStreamCdnConfigConfig() {}
    /**
     * @return The hostname of the CDN edge server to use when building CDN URLs.
     * 
     */
    public String edgeHostname() {
        return this.edgeHostname;
    }
    /**
     * @return The path to prepend when building CDN URLs.
     * 
     */
    public String edgePathPrefix() {
        return this.edgePathPrefix;
    }
    /**
     * @return The encryption key to use for edge token authentication.
     * 
     */
    public String edgeTokenKey() {
        return this.edgeTokenKey;
    }
    /**
     * @return Salt to use when encrypting authentication token.
     * 
     */
    public String edgeTokenSalt() {
        return this.edgeTokenSalt;
    }
    /**
     * @return Whether token authentication should be used at the CDN edge.
     * 
     */
    public Boolean isEdgeTokenAuth() {
        return this.isEdgeTokenAuth;
    }
    /**
     * @return The shared secret key A, two for errorless key rotation.
     * 
     */
    public String originAuthSecretKeyA() {
        return this.originAuthSecretKeyA;
    }
    /**
     * @return The shared secret key B, two for errorless key rotation.
     * 
     */
    public String originAuthSecretKeyB() {
        return this.originAuthSecretKeyB;
    }
    /**
     * @return Nonce identifier for originAuthSecretKeyA (used to determine key used to sign).
     * 
     */
    public String originAuthSecretKeyNonceA() {
        return this.originAuthSecretKeyNonceA;
    }
    /**
     * @return Nonce identifier for originAuthSecretKeyB (used to determine key used to sign).
     * 
     */
    public String originAuthSecretKeyNonceB() {
        return this.originAuthSecretKeyNonceB;
    }
    /**
     * @return The type of encryption used to compute the signature.
     * 
     */
    public String originAuthSignEncryption() {
        return this.originAuthSignEncryption;
    }
    /**
     * @return The type of data used to compute the signature.
     * 
     */
    public String originAuthSignType() {
        return this.originAuthSignType;
    }
    /**
     * @return The name of the CDN configuration type.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamCdnConfigConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String edgeHostname;
        private String edgePathPrefix;
        private String edgeTokenKey;
        private String edgeTokenSalt;
        private Boolean isEdgeTokenAuth;
        private String originAuthSecretKeyA;
        private String originAuthSecretKeyB;
        private String originAuthSecretKeyNonceA;
        private String originAuthSecretKeyNonceB;
        private String originAuthSignEncryption;
        private String originAuthSignType;
        private String type;
        public Builder() {}
        public Builder(GetStreamCdnConfigConfig defaults) {
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
        public Builder edgeHostname(String edgeHostname) {
            this.edgeHostname = Objects.requireNonNull(edgeHostname);
            return this;
        }
        @CustomType.Setter
        public Builder edgePathPrefix(String edgePathPrefix) {
            this.edgePathPrefix = Objects.requireNonNull(edgePathPrefix);
            return this;
        }
        @CustomType.Setter
        public Builder edgeTokenKey(String edgeTokenKey) {
            this.edgeTokenKey = Objects.requireNonNull(edgeTokenKey);
            return this;
        }
        @CustomType.Setter
        public Builder edgeTokenSalt(String edgeTokenSalt) {
            this.edgeTokenSalt = Objects.requireNonNull(edgeTokenSalt);
            return this;
        }
        @CustomType.Setter
        public Builder isEdgeTokenAuth(Boolean isEdgeTokenAuth) {
            this.isEdgeTokenAuth = Objects.requireNonNull(isEdgeTokenAuth);
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyA(String originAuthSecretKeyA) {
            this.originAuthSecretKeyA = Objects.requireNonNull(originAuthSecretKeyA);
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyB(String originAuthSecretKeyB) {
            this.originAuthSecretKeyB = Objects.requireNonNull(originAuthSecretKeyB);
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyNonceA(String originAuthSecretKeyNonceA) {
            this.originAuthSecretKeyNonceA = Objects.requireNonNull(originAuthSecretKeyNonceA);
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSecretKeyNonceB(String originAuthSecretKeyNonceB) {
            this.originAuthSecretKeyNonceB = Objects.requireNonNull(originAuthSecretKeyNonceB);
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSignEncryption(String originAuthSignEncryption) {
            this.originAuthSignEncryption = Objects.requireNonNull(originAuthSignEncryption);
            return this;
        }
        @CustomType.Setter
        public Builder originAuthSignType(String originAuthSignType) {
            this.originAuthSignType = Objects.requireNonNull(originAuthSignType);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetStreamCdnConfigConfig build() {
            final var o = new GetStreamCdnConfigConfig();
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