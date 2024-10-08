// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag;
import com.pulumi.oci.Identity.outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTag;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTags {
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Defined Tags
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [namespace, key, value]
     * * type: complex
     * * idcsSearchable: true
     * * required: false
     * * mutability: readWrite
     * * multiValued: true
     * * returned: default
     * 
     */
    private @Nullable List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag> definedTags;
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Freeform Tags
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * type: complex
     * * required: false
     * * mutability: readWrite
     * * returned: default
     * * multiValued: true
     * 
     */
    private @Nullable List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTag> freeformTags;
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tag slug
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * type: binary
     * * mutability: readOnly
     * * returned: request
     * 
     */
    private @Nullable String tagSlug;

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTags() {}
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Defined Tags
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [namespace, key, value]
     * * type: complex
     * * idcsSearchable: true
     * * required: false
     * * mutability: readWrite
     * * multiValued: true
     * * returned: default
     * 
     */
    public List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag> definedTags() {
        return this.definedTags == null ? List.of() : this.definedTags;
    }
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Freeform Tags
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * type: complex
     * * required: false
     * * mutability: readWrite
     * * returned: default
     * * multiValued: true
     * 
     */
    public List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTag> freeformTags() {
        return this.freeformTags == null ? List.of() : this.freeformTags;
    }
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tag slug
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * type: binary
     * * mutability: readOnly
     * * returned: request
     * 
     */
    public Optional<String> tagSlug() {
        return Optional.ofNullable(this.tagSlug);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTags defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag> definedTags;
        private @Nullable List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTag> freeformTags;
        private @Nullable String tagSlug;
        public Builder() {}
        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTags defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.tagSlug = defaults.tagSlug;
        }

        @CustomType.Setter
        public Builder definedTags(@Nullable List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag> definedTags) {

            this.definedTags = definedTags;
            return this;
        }
        public Builder definedTags(DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag... definedTags) {
            return definedTags(List.of(definedTags));
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTag> freeformTags) {

            this.freeformTags = freeformTags;
            return this;
        }
        public Builder freeformTags(DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTag... freeformTags) {
            return freeformTags(List.of(freeformTags));
        }
        @CustomType.Setter
        public Builder tagSlug(@Nullable String tagSlug) {

            this.tagSlug = tagSlug;
            return this;
        }
        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTags build() {
            final var _resultValue = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTags();
            _resultValue.definedTags = definedTags;
            _resultValue.freeformTags = freeformTags;
            _resultValue.tagSlug = tagSlug;
            return _resultValue;
        }
    }
}
