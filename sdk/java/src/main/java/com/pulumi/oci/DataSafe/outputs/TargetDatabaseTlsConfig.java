// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TargetDatabaseTlsConfig {
    /**
     * @return (Updatable) The format of the certificate store.
     * 
     */
    private @Nullable String certificateStoreType;
    /**
     * @return (Updatable) Base64 encoded string of key store file content.
     * 
     */
    private @Nullable String keyStoreContent;
    /**
     * @return (Updatable) Status to represent whether the database connection is TLS enabled or not.
     * 
     */
    private String status;
    /**
     * @return (Updatable) The password to read the trust store and key store files, if they are password protected.
     * 
     */
    private @Nullable String storePassword;
    /**
     * @return (Updatable) Base64 encoded string of trust store file content.
     * 
     */
    private @Nullable String trustStoreContent;

    private TargetDatabaseTlsConfig() {}
    /**
     * @return (Updatable) The format of the certificate store.
     * 
     */
    public Optional<String> certificateStoreType() {
        return Optional.ofNullable(this.certificateStoreType);
    }
    /**
     * @return (Updatable) Base64 encoded string of key store file content.
     * 
     */
    public Optional<String> keyStoreContent() {
        return Optional.ofNullable(this.keyStoreContent);
    }
    /**
     * @return (Updatable) Status to represent whether the database connection is TLS enabled or not.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return (Updatable) The password to read the trust store and key store files, if they are password protected.
     * 
     */
    public Optional<String> storePassword() {
        return Optional.ofNullable(this.storePassword);
    }
    /**
     * @return (Updatable) Base64 encoded string of trust store file content.
     * 
     */
    public Optional<String> trustStoreContent() {
        return Optional.ofNullable(this.trustStoreContent);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetDatabaseTlsConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String certificateStoreType;
        private @Nullable String keyStoreContent;
        private String status;
        private @Nullable String storePassword;
        private @Nullable String trustStoreContent;
        public Builder() {}
        public Builder(TargetDatabaseTlsConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateStoreType = defaults.certificateStoreType;
    	      this.keyStoreContent = defaults.keyStoreContent;
    	      this.status = defaults.status;
    	      this.storePassword = defaults.storePassword;
    	      this.trustStoreContent = defaults.trustStoreContent;
        }

        @CustomType.Setter
        public Builder certificateStoreType(@Nullable String certificateStoreType) {
            this.certificateStoreType = certificateStoreType;
            return this;
        }
        @CustomType.Setter
        public Builder keyStoreContent(@Nullable String keyStoreContent) {
            this.keyStoreContent = keyStoreContent;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder storePassword(@Nullable String storePassword) {
            this.storePassword = storePassword;
            return this;
        }
        @CustomType.Setter
        public Builder trustStoreContent(@Nullable String trustStoreContent) {
            this.trustStoreContent = trustStoreContent;
            return this;
        }
        public TargetDatabaseTlsConfig build() {
            final var o = new TargetDatabaseTlsConfig();
            o.certificateStoreType = certificateStoreType;
            o.keyStoreContent = keyStoreContent;
            o.status = status;
            o.storePassword = storePassword;
            o.trustStoreContent = trustStoreContent;
            return o;
        }
    }
}