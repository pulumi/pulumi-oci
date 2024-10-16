// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp {
    /**
     * @return (Updatable) The type of salt that the system will use to encrypt Kerberos-specific artifacts of this App unless another type of salt is specified.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String defaultEncryptionSaltType;
    /**
     * @return (Updatable) The primary key that the system should use to encrypt artifacts that are specific to this Kerberos realm -- for example, to encrypt the Principal Key in each KerberosRealmUser.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String masterKey;
    /**
     * @return (Updatable) Max Renewable Age in seconds
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer maxRenewableAge;
    /**
     * @return (Updatable) Max Ticket Life in seconds
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer maxTicketLife;
    /**
     * @return (Updatable) The name of the Kerberos Realm that this App uses for authentication.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String realmName;
    /**
     * @return (Updatable) The types of salt that are available for the system to use when encrypting Kerberos-specific artifacts for this App.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable List<String> supportedEncryptionSaltTypes;
    /**
     * @return (Updatable) Ticket Flags
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: integer
     * * uniqueness: none
     * 
     */
    private @Nullable Integer ticketFlags;

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp() {}
    /**
     * @return (Updatable) The type of salt that the system will use to encrypt Kerberos-specific artifacts of this App unless another type of salt is specified.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> defaultEncryptionSaltType() {
        return Optional.ofNullable(this.defaultEncryptionSaltType);
    }
    /**
     * @return (Updatable) The primary key that the system should use to encrypt artifacts that are specific to this Kerberos realm -- for example, to encrypt the Principal Key in each KerberosRealmUser.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> masterKey() {
        return Optional.ofNullable(this.masterKey);
    }
    /**
     * @return (Updatable) Max Renewable Age in seconds
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> maxRenewableAge() {
        return Optional.ofNullable(this.maxRenewableAge);
    }
    /**
     * @return (Updatable) Max Ticket Life in seconds
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> maxTicketLife() {
        return Optional.ofNullable(this.maxTicketLife);
    }
    /**
     * @return (Updatable) The name of the Kerberos Realm that this App uses for authentication.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> realmName() {
        return Optional.ofNullable(this.realmName);
    }
    /**
     * @return (Updatable) The types of salt that are available for the system to use when encrypting Kerberos-specific artifacts for this App.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public List<String> supportedEncryptionSaltTypes() {
        return this.supportedEncryptionSaltTypes == null ? List.of() : this.supportedEncryptionSaltTypes;
    }
    /**
     * @return (Updatable) Ticket Flags
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Integer> ticketFlags() {
        return Optional.ofNullable(this.ticketFlags);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String defaultEncryptionSaltType;
        private @Nullable String masterKey;
        private @Nullable Integer maxRenewableAge;
        private @Nullable Integer maxTicketLife;
        private @Nullable String realmName;
        private @Nullable List<String> supportedEncryptionSaltTypes;
        private @Nullable Integer ticketFlags;
        public Builder() {}
        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultEncryptionSaltType = defaults.defaultEncryptionSaltType;
    	      this.masterKey = defaults.masterKey;
    	      this.maxRenewableAge = defaults.maxRenewableAge;
    	      this.maxTicketLife = defaults.maxTicketLife;
    	      this.realmName = defaults.realmName;
    	      this.supportedEncryptionSaltTypes = defaults.supportedEncryptionSaltTypes;
    	      this.ticketFlags = defaults.ticketFlags;
        }

        @CustomType.Setter
        public Builder defaultEncryptionSaltType(@Nullable String defaultEncryptionSaltType) {

            this.defaultEncryptionSaltType = defaultEncryptionSaltType;
            return this;
        }
        @CustomType.Setter
        public Builder masterKey(@Nullable String masterKey) {

            this.masterKey = masterKey;
            return this;
        }
        @CustomType.Setter
        public Builder maxRenewableAge(@Nullable Integer maxRenewableAge) {

            this.maxRenewableAge = maxRenewableAge;
            return this;
        }
        @CustomType.Setter
        public Builder maxTicketLife(@Nullable Integer maxTicketLife) {

            this.maxTicketLife = maxTicketLife;
            return this;
        }
        @CustomType.Setter
        public Builder realmName(@Nullable String realmName) {

            this.realmName = realmName;
            return this;
        }
        @CustomType.Setter
        public Builder supportedEncryptionSaltTypes(@Nullable List<String> supportedEncryptionSaltTypes) {

            this.supportedEncryptionSaltTypes = supportedEncryptionSaltTypes;
            return this;
        }
        public Builder supportedEncryptionSaltTypes(String... supportedEncryptionSaltTypes) {
            return supportedEncryptionSaltTypes(List.of(supportedEncryptionSaltTypes));
        }
        @CustomType.Setter
        public Builder ticketFlags(@Nullable Integer ticketFlags) {

            this.ticketFlags = ticketFlags;
            return this;
        }
        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp build() {
            final var _resultValue = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp();
            _resultValue.defaultEncryptionSaltType = defaultEncryptionSaltType;
            _resultValue.masterKey = masterKey;
            _resultValue.maxRenewableAge = maxRenewableAge;
            _resultValue.maxTicketLife = maxTicketLife;
            _resultValue.realmName = realmName;
            _resultValue.supportedEncryptionSaltTypes = supportedEncryptionSaltTypes;
            _resultValue.ticketFlags = ticketFlags;
            return _resultValue;
        }
    }
}
