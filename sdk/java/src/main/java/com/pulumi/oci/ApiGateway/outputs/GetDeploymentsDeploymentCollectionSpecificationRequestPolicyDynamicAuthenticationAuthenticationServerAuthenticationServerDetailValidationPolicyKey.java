// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey {
    /**
     * @return The algorithm intended for use with this key.
     * 
     */
    private String alg;
    /**
     * @return The base64 url encoded exponent of the RSA public key represented by this key.
     * 
     */
    private String e;
    /**
     * @return The format of the public key.
     * 
     */
    private String format;
    /**
     * @return Information around the values for selector of an authentication/ routing branch.
     * 
     */
    private String key;
    /**
     * @return The operations for which this key is to be used.
     * 
     */
    private List<String> keyOps;
    /**
     * @return A unique key ID. This key will be used to verify the signature of a JWT with matching &#34;kid&#34;.
     * 
     */
    private String kid;
    /**
     * @return The key type.
     * 
     */
    private String kty;
    /**
     * @return The base64 url encoded modulus of the RSA public key represented by this key.
     * 
     */
    private String n;
    /**
     * @return The intended use of the public key.
     * 
     */
    private String use;

    private GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey() {}
    /**
     * @return The algorithm intended for use with this key.
     * 
     */
    public String alg() {
        return this.alg;
    }
    /**
     * @return The base64 url encoded exponent of the RSA public key represented by this key.
     * 
     */
    public String e() {
        return this.e;
    }
    /**
     * @return The format of the public key.
     * 
     */
    public String format() {
        return this.format;
    }
    /**
     * @return Information around the values for selector of an authentication/ routing branch.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The operations for which this key is to be used.
     * 
     */
    public List<String> keyOps() {
        return this.keyOps;
    }
    /**
     * @return A unique key ID. This key will be used to verify the signature of a JWT with matching &#34;kid&#34;.
     * 
     */
    public String kid() {
        return this.kid;
    }
    /**
     * @return The key type.
     * 
     */
    public String kty() {
        return this.kty;
    }
    /**
     * @return The base64 url encoded modulus of the RSA public key represented by this key.
     * 
     */
    public String n() {
        return this.n;
    }
    /**
     * @return The intended use of the public key.
     * 
     */
    public String use() {
        return this.use;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String alg;
        private String e;
        private String format;
        private String key;
        private List<String> keyOps;
        private String kid;
        private String kty;
        private String n;
        private String use;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alg = defaults.alg;
    	      this.e = defaults.e;
    	      this.format = defaults.format;
    	      this.key = defaults.key;
    	      this.keyOps = defaults.keyOps;
    	      this.kid = defaults.kid;
    	      this.kty = defaults.kty;
    	      this.n = defaults.n;
    	      this.use = defaults.use;
        }

        @CustomType.Setter
        public Builder alg(String alg) {
            if (alg == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "alg");
            }
            this.alg = alg;
            return this;
        }
        @CustomType.Setter
        public Builder e(String e) {
            if (e == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "e");
            }
            this.e = e;
            return this;
        }
        @CustomType.Setter
        public Builder format(String format) {
            if (format == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "format");
            }
            this.format = format;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder keyOps(List<String> keyOps) {
            if (keyOps == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "keyOps");
            }
            this.keyOps = keyOps;
            return this;
        }
        public Builder keyOps(String... keyOps) {
            return keyOps(List.of(keyOps));
        }
        @CustomType.Setter
        public Builder kid(String kid) {
            if (kid == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "kid");
            }
            this.kid = kid;
            return this;
        }
        @CustomType.Setter
        public Builder kty(String kty) {
            if (kty == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "kty");
            }
            this.kty = kty;
            return this;
        }
        @CustomType.Setter
        public Builder n(String n) {
            if (n == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "n");
            }
            this.n = n;
            return this;
        }
        @CustomType.Setter
        public Builder use(String use) {
            if (use == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey", "use");
            }
            this.use = use;
            return this;
        }
        public GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey build() {
            final var _resultValue = new GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyKey();
            _resultValue.alg = alg;
            _resultValue.e = e;
            _resultValue.format = format;
            _resultValue.key = key;
            _resultValue.keyOps = keyOps;
            _resultValue.kid = kid;
            _resultValue.kty = kty;
            _resultValue.n = n;
            _resultValue.use = use;
            return _resultValue;
        }
    }
}
