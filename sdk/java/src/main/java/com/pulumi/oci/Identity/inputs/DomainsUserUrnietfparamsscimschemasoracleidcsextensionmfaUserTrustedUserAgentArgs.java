// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs Empty = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs();

    /**
     * (Updatable) A human-readable identifier for this trusted user agent, used primarily for display purposes. READ-ONLY.
     * 
     * **Added In:** 18.3.6
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) A human-readable identifier for this trusted user agent, used primarily for display purposes. READ-ONLY.
     * 
     * **Added In:** 18.3.6
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * (Updatable) The URI of the corresponding trusted user agent resource.
     * 
     * **Added In:** 18.3.6
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
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) The URI of the corresponding trusted user agent resource.
     * 
     * **Added In:** 18.3.6
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
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) The user&#39;s trusted user agent identifier.
     * 
     * **Added In:** 18.3.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) The user&#39;s trusted user agent identifier.
     * 
     * **Added In:** 18.3.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs() {}

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs(DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs $) {
        this.display = $.display;
        this.ref = $.ref;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs $;

        public Builder() {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs();
        }

        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs defaults) {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) A human-readable identifier for this trusted user agent, used primarily for display purposes. READ-ONLY.
         * 
         * **Added In:** 18.3.6
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) A human-readable identifier for this trusted user agent, used primarily for display purposes. READ-ONLY.
         * 
         * **Added In:** 18.3.6
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param ref (Updatable) The URI of the corresponding trusted user agent resource.
         * 
         * **Added In:** 18.3.6
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
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) The URI of the corresponding trusted user agent resource.
         * 
         * **Added In:** 18.3.6
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
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param value (Updatable) The user&#39;s trusted user agent identifier.
         * 
         * **Added In:** 18.3.6
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The user&#39;s trusted user agent identifier.
         * 
         * **Added In:** 18.3.6
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs build() {
            if ($.value == null) {
                throw new MissingRequiredPropertyException("DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentArgs", "value");
            }
            return $;
        }
    }

}
