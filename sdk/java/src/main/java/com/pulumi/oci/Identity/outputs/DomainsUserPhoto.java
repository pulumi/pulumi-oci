// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsUserPhoto {
    /**
     * @return (Updatable) A human readable name, primarily used for display purposes.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String display;
    /**
     * @return (Updatable) A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute, e.g., the preferred photo or thumbnail. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    private @Nullable Boolean primary;
    /**
     * @return (Updatable) A label indicating the attribute&#39;s function; e.g., &#39;photo&#39; or &#39;thumbnail&#39;.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private String type;
    /**
     * @return (Updatable) URL of a photo for the User
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    private String value;

    private DomainsUserPhoto() {}
    /**
     * @return (Updatable) A human readable name, primarily used for display purposes.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> display() {
        return Optional.ofNullable(this.display);
    }
    /**
     * @return (Updatable) A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute, e.g., the preferred photo or thumbnail. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Boolean> primary() {
        return Optional.ofNullable(this.primary);
    }
    /**
     * @return (Updatable) A label indicating the attribute&#39;s function; e.g., &#39;photo&#39; or &#39;thumbnail&#39;.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
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
     * @return (Updatable) URL of a photo for the User
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsUserPhoto defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String display;
        private @Nullable Boolean primary;
        private String type;
        private String value;
        public Builder() {}
        public Builder(DomainsUserPhoto defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.primary = defaults.primary;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(@Nullable String display) {

            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder primary(@Nullable Boolean primary) {

            this.primary = primary;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("DomainsUserPhoto", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("DomainsUserPhoto", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsUserPhoto build() {
            final var _resultValue = new DomainsUserPhoto();
            _resultValue.display = display;
            _resultValue.primary = primary;
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
