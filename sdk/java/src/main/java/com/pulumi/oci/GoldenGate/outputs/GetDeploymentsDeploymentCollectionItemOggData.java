// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionItemOggData {
    private String adminPassword;
    /**
     * @return The GoldenGate deployment console username.
     * 
     */
    private String adminUsername;
    /**
     * @return A PEM-encoded SSL certificate.
     * 
     */
    private String certificate;
    /**
     * @return The name given to the GoldenGate service deployment. The name must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
     * 
     */
    private String deploymentName;
    private String key;
    /**
     * @return Version of OGG
     * 
     */
    private String oggVersion;

    private GetDeploymentsDeploymentCollectionItemOggData() {}
    public String adminPassword() {
        return this.adminPassword;
    }
    /**
     * @return The GoldenGate deployment console username.
     * 
     */
    public String adminUsername() {
        return this.adminUsername;
    }
    /**
     * @return A PEM-encoded SSL certificate.
     * 
     */
    public String certificate() {
        return this.certificate;
    }
    /**
     * @return The name given to the GoldenGate service deployment. The name must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
     * 
     */
    public String deploymentName() {
        return this.deploymentName;
    }
    public String key() {
        return this.key;
    }
    /**
     * @return Version of OGG
     * 
     */
    public String oggVersion() {
        return this.oggVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionItemOggData defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminPassword;
        private String adminUsername;
        private String certificate;
        private String deploymentName;
        private String key;
        private String oggVersion;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionItemOggData defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminPassword = defaults.adminPassword;
    	      this.adminUsername = defaults.adminUsername;
    	      this.certificate = defaults.certificate;
    	      this.deploymentName = defaults.deploymentName;
    	      this.key = defaults.key;
    	      this.oggVersion = defaults.oggVersion;
        }

        @CustomType.Setter
        public Builder adminPassword(String adminPassword) {
            this.adminPassword = Objects.requireNonNull(adminPassword);
            return this;
        }
        @CustomType.Setter
        public Builder adminUsername(String adminUsername) {
            this.adminUsername = Objects.requireNonNull(adminUsername);
            return this;
        }
        @CustomType.Setter
        public Builder certificate(String certificate) {
            this.certificate = Objects.requireNonNull(certificate);
            return this;
        }
        @CustomType.Setter
        public Builder deploymentName(String deploymentName) {
            this.deploymentName = Objects.requireNonNull(deploymentName);
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder oggVersion(String oggVersion) {
            this.oggVersion = Objects.requireNonNull(oggVersion);
            return this;
        }
        public GetDeploymentsDeploymentCollectionItemOggData build() {
            final var o = new GetDeploymentsDeploymentCollectionItemOggData();
            o.adminPassword = adminPassword;
            o.adminUsername = adminUsername;
            o.certificate = certificate;
            o.deploymentName = deploymentName;
            o.key = key;
            o.oggVersion = oggVersion;
            return o;
        }
    }
}