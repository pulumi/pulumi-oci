// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerInstances.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetContainerInstancesContainerInstanceCollectionItemImagePullSecret {
    private String password;
    /**
     * @return The registry endpoint of the container image.
     * 
     */
    private String registryEndpoint;
    /**
     * @return The OCID of the secret for registry credentials.
     * 
     */
    private String secretId;
    /**
     * @return The type of ImagePullSecret.
     * 
     */
    private String secretType;
    private String username;

    private GetContainerInstancesContainerInstanceCollectionItemImagePullSecret() {}
    public String password() {
        return this.password;
    }
    /**
     * @return The registry endpoint of the container image.
     * 
     */
    public String registryEndpoint() {
        return this.registryEndpoint;
    }
    /**
     * @return The OCID of the secret for registry credentials.
     * 
     */
    public String secretId() {
        return this.secretId;
    }
    /**
     * @return The type of ImagePullSecret.
     * 
     */
    public String secretType() {
        return this.secretType;
    }
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerInstancesContainerInstanceCollectionItemImagePullSecret defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String password;
        private String registryEndpoint;
        private String secretId;
        private String secretType;
        private String username;
        public Builder() {}
        public Builder(GetContainerInstancesContainerInstanceCollectionItemImagePullSecret defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.password = defaults.password;
    	      this.registryEndpoint = defaults.registryEndpoint;
    	      this.secretId = defaults.secretId;
    	      this.secretType = defaults.secretType;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder password(String password) {
            this.password = Objects.requireNonNull(password);
            return this;
        }
        @CustomType.Setter
        public Builder registryEndpoint(String registryEndpoint) {
            this.registryEndpoint = Objects.requireNonNull(registryEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder secretId(String secretId) {
            this.secretId = Objects.requireNonNull(secretId);
            return this;
        }
        @CustomType.Setter
        public Builder secretType(String secretType) {
            this.secretType = Objects.requireNonNull(secretType);
            return this;
        }
        @CustomType.Setter
        public Builder username(String username) {
            this.username = Objects.requireNonNull(username);
            return this;
        }
        public GetContainerInstancesContainerInstanceCollectionItemImagePullSecret build() {
            final var o = new GetContainerInstancesContainerInstanceCollectionItemImagePullSecret();
            o.password = password;
            o.registryEndpoint = registryEndpoint;
            o.secretId = secretId;
            o.secretType = secretType;
            o.username = username;
            return o;
        }
    }
}