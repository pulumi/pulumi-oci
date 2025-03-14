// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser {
    /**
     * @return (Updatable) DB global roles to which the user is granted access.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable List<String> dbGlobalRoles;
    /**
     * @return (Updatable) DB domain level schema to which the user is granted access.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String domainLevelSchema;
    /**
     * @return (Updatable) DB instance level schema to which the user is granted access.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String instanceLevelSchema;
    /**
     * @return (Updatable) If true, indicates this is a database user.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: boolean
     * * uniqueness: none
     * 
     */
    private @Nullable Boolean isDbUser;
    /**
     * @return (Updatable) Password Verifiers for DB User.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [type]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     * 
     */
    private @Nullable List<DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier> passwordVerifiers;

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser() {}
    /**
     * @return (Updatable) DB global roles to which the user is granted access.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public List<String> dbGlobalRoles() {
        return this.dbGlobalRoles == null ? List.of() : this.dbGlobalRoles;
    }
    /**
     * @return (Updatable) DB domain level schema to which the user is granted access.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> domainLevelSchema() {
        return Optional.ofNullable(this.domainLevelSchema);
    }
    /**
     * @return (Updatable) DB instance level schema to which the user is granted access.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * idcsSensitive: none
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> instanceLevelSchema() {
        return Optional.ofNullable(this.instanceLevelSchema);
    }
    /**
     * @return (Updatable) If true, indicates this is a database user.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Boolean> isDbUser() {
        return Optional.ofNullable(this.isDbUser);
    }
    /**
     * @return (Updatable) Password Verifiers for DB User.
     * 
     * **Added In:** 18.2.2
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [type]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     * 
     */
    public List<DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier> passwordVerifiers() {
        return this.passwordVerifiers == null ? List.of() : this.passwordVerifiers;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> dbGlobalRoles;
        private @Nullable String domainLevelSchema;
        private @Nullable String instanceLevelSchema;
        private @Nullable Boolean isDbUser;
        private @Nullable List<DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier> passwordVerifiers;
        public Builder() {}
        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbGlobalRoles = defaults.dbGlobalRoles;
    	      this.domainLevelSchema = defaults.domainLevelSchema;
    	      this.instanceLevelSchema = defaults.instanceLevelSchema;
    	      this.isDbUser = defaults.isDbUser;
    	      this.passwordVerifiers = defaults.passwordVerifiers;
        }

        @CustomType.Setter
        public Builder dbGlobalRoles(@Nullable List<String> dbGlobalRoles) {

            this.dbGlobalRoles = dbGlobalRoles;
            return this;
        }
        public Builder dbGlobalRoles(String... dbGlobalRoles) {
            return dbGlobalRoles(List.of(dbGlobalRoles));
        }
        @CustomType.Setter
        public Builder domainLevelSchema(@Nullable String domainLevelSchema) {

            this.domainLevelSchema = domainLevelSchema;
            return this;
        }
        @CustomType.Setter
        public Builder instanceLevelSchema(@Nullable String instanceLevelSchema) {

            this.instanceLevelSchema = instanceLevelSchema;
            return this;
        }
        @CustomType.Setter
        public Builder isDbUser(@Nullable Boolean isDbUser) {

            this.isDbUser = isDbUser;
            return this;
        }
        @CustomType.Setter
        public Builder passwordVerifiers(@Nullable List<DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier> passwordVerifiers) {

            this.passwordVerifiers = passwordVerifiers;
            return this;
        }
        public Builder passwordVerifiers(DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier... passwordVerifiers) {
            return passwordVerifiers(List.of(passwordVerifiers));
        }
        public DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser build() {
            final var _resultValue = new DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser();
            _resultValue.dbGlobalRoles = dbGlobalRoles;
            _resultValue.domainLevelSchema = domainLevelSchema;
            _resultValue.instanceLevelSchema = instanceLevelSchema;
            _resultValue.isDbUser = isDbUser;
            _resultValue.passwordVerifiers = passwordVerifiers;
            return _resultValue;
        }
    }
}
