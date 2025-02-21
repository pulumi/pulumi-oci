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
public final class DomainsUserIm {
    /**
     * @return (Updatable) A human-readable name, primarily used for display purposes
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
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
     * @return (Updatable) A Boolean value that indicates the &#39;primary&#39; or preferred attribute value for this attribute--for example, the preferred messenger or primary messenger. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
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
     * @return (Updatable) A label that indicates the attribute&#39;s function--for example, &#39;aim&#39;, &#39;gtalk&#39;, or &#39;mobile&#39;
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
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
     * @return (Updatable) User&#39;s instant messaging address
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private String value;

    private DomainsUserIm() {}
    /**
     * @return (Updatable) A human-readable name, primarily used for display purposes
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
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
     * @return (Updatable) A Boolean value that indicates the &#39;primary&#39; or preferred attribute value for this attribute--for example, the preferred messenger or primary messenger. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
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
     * @return (Updatable) A label that indicates the attribute&#39;s function--for example, &#39;aim&#39;, &#39;gtalk&#39;, or &#39;mobile&#39;
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
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
     * @return (Updatable) User&#39;s instant messaging address
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
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

    public static Builder builder(DomainsUserIm defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String display;
        private @Nullable Boolean primary;
        private String type;
        private String value;
        public Builder() {}
        public Builder(DomainsUserIm defaults) {
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
              throw new MissingRequiredPropertyException("DomainsUserIm", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("DomainsUserIm", "value");
            }
            this.value = value;
            return this;
        }
        public DomainsUserIm build() {
            final var _resultValue = new DomainsUserIm();
            _resultValue.display = display;
            _resultValue.primary = primary;
            _resultValue.type = type;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
