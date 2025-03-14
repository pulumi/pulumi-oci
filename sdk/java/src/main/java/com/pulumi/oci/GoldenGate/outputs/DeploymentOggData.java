// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.outputs.DeploymentOggDataGroupToRolesMapping;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentOggData {
    /**
     * @return (Updatable) The password associated with the GoldenGate deployment console username. The password must be 8 to 30 characters long and must contain at least 1 uppercase, 1 lowercase, 1 numeric, and 1 special character. Special characters such as ‘$’, ‘^’, or ‘?’ are not allowed. This field will be deprecated and replaced by &#34;passwordSecretId&#34;.
     * 
     */
    private @Nullable String adminPassword;
    /**
     * @return (Updatable) The GoldenGate deployment console username.
     * 
     */
    private @Nullable String adminUsername;
    /**
     * @return (Updatable) The base64 encoded content of the PEM file containing the SSL certificate.
     * 
     */
    private @Nullable String certificate;
    /**
     * @return (Updatable) The type of credential store for OGG.
     * 
     */
    private @Nullable String credentialStore;
    /**
     * @return The name given to the GoldenGate service deployment. The name must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
     * 
     */
    private String deploymentName;
    /**
     * @return (Updatable) Defines the IDP Groups to GoldenGate roles mapping. This field is used only for IAM deployment and does not have any impact on non-IAM deployments. For IAM deployment, when user does not specify this mapping, then it has null value and default mapping is used. User belonging to each group can only perform the actions according to the role the respective group is mapped to.
     * 
     */
    private @Nullable DeploymentOggDataGroupToRolesMapping groupToRolesMapping;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Identity Domain when IAM credential store is used.
     * 
     */
    private @Nullable String identityDomainId;
    /**
     * @return (Updatable) The base64 encoded content of the PEM file containing the private key.
     * 
     */
    private @Nullable String key;
    /**
     * @return Version of OGG
     * 
     */
    private @Nullable String oggVersion;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the deployment password is stored.
     * 
     */
    private @Nullable String passwordSecretId;

    private DeploymentOggData() {}
    /**
     * @return (Updatable) The password associated with the GoldenGate deployment console username. The password must be 8 to 30 characters long and must contain at least 1 uppercase, 1 lowercase, 1 numeric, and 1 special character. Special characters such as ‘$’, ‘^’, or ‘?’ are not allowed. This field will be deprecated and replaced by &#34;passwordSecretId&#34;.
     * 
     */
    public Optional<String> adminPassword() {
        return Optional.ofNullable(this.adminPassword);
    }
    /**
     * @return (Updatable) The GoldenGate deployment console username.
     * 
     */
    public Optional<String> adminUsername() {
        return Optional.ofNullable(this.adminUsername);
    }
    /**
     * @return (Updatable) The base64 encoded content of the PEM file containing the SSL certificate.
     * 
     */
    public Optional<String> certificate() {
        return Optional.ofNullable(this.certificate);
    }
    /**
     * @return (Updatable) The type of credential store for OGG.
     * 
     */
    public Optional<String> credentialStore() {
        return Optional.ofNullable(this.credentialStore);
    }
    /**
     * @return The name given to the GoldenGate service deployment. The name must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
     * 
     */
    public String deploymentName() {
        return this.deploymentName;
    }
    /**
     * @return (Updatable) Defines the IDP Groups to GoldenGate roles mapping. This field is used only for IAM deployment and does not have any impact on non-IAM deployments. For IAM deployment, when user does not specify this mapping, then it has null value and default mapping is used. User belonging to each group can only perform the actions according to the role the respective group is mapped to.
     * 
     */
    public Optional<DeploymentOggDataGroupToRolesMapping> groupToRolesMapping() {
        return Optional.ofNullable(this.groupToRolesMapping);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Identity Domain when IAM credential store is used.
     * 
     */
    public Optional<String> identityDomainId() {
        return Optional.ofNullable(this.identityDomainId);
    }
    /**
     * @return (Updatable) The base64 encoded content of the PEM file containing the private key.
     * 
     */
    public Optional<String> key() {
        return Optional.ofNullable(this.key);
    }
    /**
     * @return Version of OGG
     * 
     */
    public Optional<String> oggVersion() {
        return Optional.ofNullable(this.oggVersion);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the deployment password is stored.
     * 
     */
    public Optional<String> passwordSecretId() {
        return Optional.ofNullable(this.passwordSecretId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentOggData defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String adminPassword;
        private @Nullable String adminUsername;
        private @Nullable String certificate;
        private @Nullable String credentialStore;
        private String deploymentName;
        private @Nullable DeploymentOggDataGroupToRolesMapping groupToRolesMapping;
        private @Nullable String identityDomainId;
        private @Nullable String key;
        private @Nullable String oggVersion;
        private @Nullable String passwordSecretId;
        public Builder() {}
        public Builder(DeploymentOggData defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminPassword = defaults.adminPassword;
    	      this.adminUsername = defaults.adminUsername;
    	      this.certificate = defaults.certificate;
    	      this.credentialStore = defaults.credentialStore;
    	      this.deploymentName = defaults.deploymentName;
    	      this.groupToRolesMapping = defaults.groupToRolesMapping;
    	      this.identityDomainId = defaults.identityDomainId;
    	      this.key = defaults.key;
    	      this.oggVersion = defaults.oggVersion;
    	      this.passwordSecretId = defaults.passwordSecretId;
        }

        @CustomType.Setter
        public Builder adminPassword(@Nullable String adminPassword) {

            this.adminPassword = adminPassword;
            return this;
        }
        @CustomType.Setter
        public Builder adminUsername(@Nullable String adminUsername) {

            this.adminUsername = adminUsername;
            return this;
        }
        @CustomType.Setter
        public Builder certificate(@Nullable String certificate) {

            this.certificate = certificate;
            return this;
        }
        @CustomType.Setter
        public Builder credentialStore(@Nullable String credentialStore) {

            this.credentialStore = credentialStore;
            return this;
        }
        @CustomType.Setter
        public Builder deploymentName(String deploymentName) {
            if (deploymentName == null) {
              throw new MissingRequiredPropertyException("DeploymentOggData", "deploymentName");
            }
            this.deploymentName = deploymentName;
            return this;
        }
        @CustomType.Setter
        public Builder groupToRolesMapping(@Nullable DeploymentOggDataGroupToRolesMapping groupToRolesMapping) {

            this.groupToRolesMapping = groupToRolesMapping;
            return this;
        }
        @CustomType.Setter
        public Builder identityDomainId(@Nullable String identityDomainId) {

            this.identityDomainId = identityDomainId;
            return this;
        }
        @CustomType.Setter
        public Builder key(@Nullable String key) {

            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder oggVersion(@Nullable String oggVersion) {

            this.oggVersion = oggVersion;
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(@Nullable String passwordSecretId) {

            this.passwordSecretId = passwordSecretId;
            return this;
        }
        public DeploymentOggData build() {
            final var _resultValue = new DeploymentOggData();
            _resultValue.adminPassword = adminPassword;
            _resultValue.adminUsername = adminUsername;
            _resultValue.certificate = certificate;
            _resultValue.credentialStore = credentialStore;
            _resultValue.deploymentName = deploymentName;
            _resultValue.groupToRolesMapping = groupToRolesMapping;
            _resultValue.identityDomainId = identityDomainId;
            _resultValue.key = key;
            _resultValue.oggVersion = oggVersion;
            _resultValue.passwordSecretId = passwordSecretId;
            return _resultValue;
        }
    }
}
