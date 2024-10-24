// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile {
    /**
     * @return (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String display;
    /**
     * @return (Updatable) URI of the profile.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    private @Nullable String ref;
    /**
     * @return (Updatable) Self Registration Profile Id
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    private String value;

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile() {}
    /**
     * @return (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> display() {
        return Optional.ofNullable(this.display);
    }
    /**
     * @return (Updatable) URI of the profile.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<String> ref() {
        return Optional.ofNullable(this.ref);
    }
    /**
     * @return (Updatable) Self Registration Profile Id
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String display;
        private @Nullable String ref;
        private String value;
        public Builder() {}
        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(@Nullable String display) {

            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {

            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile build() {
            final var _resultValue = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile();
            _resultValue.display = display;
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
