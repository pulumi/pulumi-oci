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
public final class DomainsAppRoleApp {
    /**
     * @return (Updatable) App display name
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String display;
    /**
     * @return (Updatable) Application name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String name;
    /**
     * @return (Updatable) App URI
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
     * @return (Updatable) The serviceInstanceIdentifier of the App that defines this AppRole. This value will match the opcServiceInstanceGUID of any service-instance that the App represents.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String serviceInstanceIdentifier;
    /**
     * @return App identifier
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

    private DomainsAppRoleApp() {}
    /**
     * @return (Updatable) App display name
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> display() {
        return Optional.ofNullable(this.display);
    }
    /**
     * @return (Updatable) Application name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return (Updatable) App URI
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
     * @return (Updatable) The serviceInstanceIdentifier of the App that defines this AppRole. This value will match the opcServiceInstanceGUID of any service-instance that the App represents.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> serviceInstanceIdentifier() {
        return Optional.ofNullable(this.serviceInstanceIdentifier);
    }
    /**
     * @return App identifier
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

    public static Builder builder(DomainsAppRoleApp defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String display;
        private @Nullable String name;
        private @Nullable String ref;
        private @Nullable String serviceInstanceIdentifier;
        private String value;
        public Builder() {}
        public Builder(DomainsAppRoleApp defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.name = defaults.name;
    	      this.ref = defaults.ref;
    	      this.serviceInstanceIdentifier = defaults.serviceInstanceIdentifier;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(@Nullable String display) {

            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {

            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder serviceInstanceIdentifier(@Nullable String serviceInstanceIdentifier) {

            this.serviceInstanceIdentifier = serviceInstanceIdentifier;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("DomainsAppRoleApp", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsAppRoleApp build() {
            final var _resultValue = new DomainsAppRoleApp();
            _resultValue.display = display;
            _resultValue.name = name;
            _resultValue.ref = ref;
            _resultValue.serviceInstanceIdentifier = serviceInstanceIdentifier;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
