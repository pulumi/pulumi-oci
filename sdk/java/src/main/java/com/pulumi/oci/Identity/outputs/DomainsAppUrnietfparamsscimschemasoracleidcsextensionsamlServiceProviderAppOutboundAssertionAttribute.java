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
public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute {
    /**
     * @return (Updatable) Mapped Attribute Direction
     * 
     * **Added In:** 18.2.6
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
    private @Nullable String direction;
    /**
     * @return (Updatable) Mapped Attribute URI
     * 
     * **Added In:** 18.2.6
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    private @Nullable String ref;
    /**
     * @return (Updatable) Mapped Attribute identifier
     * 
     * **Added In:** 18.2.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private String value;

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute() {}
    /**
     * @return (Updatable) Mapped Attribute Direction
     * 
     * **Added In:** 18.2.6
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
    public Optional<String> direction() {
        return Optional.ofNullable(this.direction);
    }
    /**
     * @return (Updatable) Mapped Attribute URI
     * 
     * **Added In:** 18.2.6
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
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
     * @return (Updatable) Mapped Attribute identifier
     * 
     * **Added In:** 18.2.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * mutability: readOnly
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

    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String direction;
        private @Nullable String ref;
        private String value;
        public Builder() {}
        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.direction = defaults.direction;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder direction(@Nullable String direction) {

            this.direction = direction;
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
              throw new MissingRequiredPropertyException("DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute build() {
            final var _resultValue = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttribute();
            _resultValue.direction = direction;
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
