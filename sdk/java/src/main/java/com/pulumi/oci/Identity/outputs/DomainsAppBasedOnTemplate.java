// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsAppBasedOnTemplate {
    /**
     * @return (Updatable) The most recent DateTime that the details of this Resource were updated at the Service Provider. If this Resource has never been modified since its initial creation, the value MUST be the same as the value of created. The attribute MUST be a DateTime.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     * 
     */
    private @Nullable String lastModified;
    /**
     * @return (Updatable) URI of the AppRole.
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
     * @return (Updatable) ID of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String value;
    /**
     * @return (Updatable) Unique well-known identifier used to reference connector bundle.
     * 
     * **Added In:** 19.1.4
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String wellKnownId;

    private DomainsAppBasedOnTemplate() {}
    /**
     * @return (Updatable) The most recent DateTime that the details of this Resource were updated at the Service Provider. If this Resource has never been modified since its initial creation, the value MUST be the same as the value of created. The attribute MUST be a DateTime.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     * 
     */
    public Optional<String> lastModified() {
        return Optional.ofNullable(this.lastModified);
    }
    /**
     * @return (Updatable) URI of the AppRole.
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
     * @return (Updatable) ID of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String value() {
        return this.value;
    }
    /**
     * @return (Updatable) Unique well-known identifier used to reference connector bundle.
     * 
     * **Added In:** 19.1.4
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> wellKnownId() {
        return Optional.ofNullable(this.wellKnownId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsAppBasedOnTemplate defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String lastModified;
        private @Nullable String ref;
        private String value;
        private @Nullable String wellKnownId;
        public Builder() {}
        public Builder(DomainsAppBasedOnTemplate defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.lastModified = defaults.lastModified;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
    	      this.wellKnownId = defaults.wellKnownId;
        }

        @CustomType.Setter
        public Builder lastModified(@Nullable String lastModified) {
            this.lastModified = lastModified;
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        @CustomType.Setter
        public Builder wellKnownId(@Nullable String wellKnownId) {
            this.wellKnownId = wellKnownId;
            return this;
        }
        public DomainsAppBasedOnTemplate build() {
            final var o = new DomainsAppBasedOnTemplate();
            o.lastModified = lastModified;
            o.ref = ref;
            o.value = value;
            o.wellKnownId = wellKnownId;
            return o;
        }
    }
}