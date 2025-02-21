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
public final class DomainsGrantGrantee {
    /**
     * @return (Updatable) Grantee display name
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
     * @return (Updatable) Grantee URI
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
     * @return Grantee resource type. Allowed values are User, Group, App and DynamicResourceGroup.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsCsvAttributeName: Member Type
     * * idcsDefaultValue: User
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private String type;
    /**
     * @return Grantee identifier
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsCsvAttributeName: Member
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private String value;

    private DomainsGrantGrantee() {}
    /**
     * @return (Updatable) Grantee display name
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
     * @return (Updatable) Grantee URI
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
     * @return Grantee resource type. Allowed values are User, Group, App and DynamicResourceGroup.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsCsvAttributeName: Member Type
     * * idcsDefaultValue: User
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Grantee identifier
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsCsvAttributeName: Member
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
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

    public static Builder builder(DomainsGrantGrantee defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String display;
        private @Nullable String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(DomainsGrantGrantee defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
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
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("DomainsGrantGrantee", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("DomainsGrantGrantee", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsGrantGrantee build() {
            final var _resultValue = new DomainsGrantGrantee();
            _resultValue.display = display;
            _resultValue.ref = ref;
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
